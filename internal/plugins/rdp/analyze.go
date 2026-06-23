// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdp

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

const (
	// changeThreshold: per-pixel brightness difference to count as "changed"
	changeThreshold = 30
	// minChangedPercent: minimum percentage of changed pixels for detection
	minChangedPercent = 2.0
	// maxChangedPercent: maximum percentage (above this, probably full screen change)
	maxChangedPercent = 80.0
)

const (
	// Brightness inside the box: a console is mostly dark, a dialog mostly light.
	consoleMaxMeanBrightness = 90  // <= this (0-255) reads as a dark console body
	dialogMinMeanBrightness  = 140 // >= this reads as a light dialog body

	// Size: console fills a large fraction of the screen; dialog is small.
	consoleMinAreaFrac = 0.18 // box area / screen area >= this  -> console-sized
	dialogMaxAreaFrac  = 0.12 // box area / screen area <= this  -> dialog-sized

	// Position: console anchors top-left; dialog is centered. Measured on the box's
	// top-left corner as a fraction of screen dimensions.
	consoleMaxLeftFrac  = 0.25 // minX/width  <= this -> left-anchored
	consoleMaxTopFrac   = 0.25 // minY/height <= this -> top-anchored
	dialogMinCenterFrac = 0.30 // box center within [0.30,0.70] of both axes -> centered

	// nonceMinChangedPixels: minimum pixels that must change inside the box after
	// typing the nonce to count as a shell echo. Set well above single-cursor-cell
	// blink noise (a text cell is ~8x16 px) so a blinking caret alone never confirms;
	// an echoed command line + new prompt changes thousands of pixels.
	nonceMinChangedPixels = 500
)

// changedBox is the bounding box of significantly-changed pixels plus its fill ratio.
type changedBox struct {
	minX, minY, maxX, maxY int
	fillRatio              float64
	changedCount           int
}

// regionSignal is the pre-filter's read of the changed region.
type regionSignal int

const (
	regionUnknown     regionSignal = iota // box present but signals don't agree
	regionConsoleLike                     // large + dark + top-left-ish  -> corroborates backdoor
	regionDialogLike                      // small + light + centered     -> corroborates dialog
)

// nonceResult is the tri-state outcome of behavioral confirmation. Only "confirmed"
// is decisive-positive; the other two are NEVER clean.
type nonceResult int

const (
	nonceSkipped     nonceResult = iota // heuristic didn't see a backdoor-like box; not attempted
	nonceConfirmed                      // new shell-like text rendered after typing -> real shell
	nonceUnconfirmed                    // no new render OR type/capture failed -> ambiguous
)

// bitmapDiff computes the absolute difference between two RGBA buffers.
// Returns a diff buffer of the same size where each pixel is the max channel diff.
func bitmapDiff(baseline, response []byte, width, height uint32) []byte {
	size := int(width) * int(height) * 4
	if len(baseline) < size || len(response) < size {
		return nil
	}

	diff := make([]byte, size)
	for i := 0; i < size; i += 4 {
		dr := absDiffByte(baseline[i], response[i])
		dg := absDiffByte(baseline[i+1], response[i+1])
		db := absDiffByte(baseline[i+2], response[i+2])
		maxD := maxByte(dr, maxByte(dg, db))
		diff[i] = maxD
		diff[i+1] = maxD
		diff[i+2] = maxD
		diff[i+3] = 255
	}
	return diff
}

func absDiffByte(a, b byte) byte {
	if a > b {
		return a - b
	}
	return b - a
}

func maxByte(a, b byte) byte {
	if a > b {
		return a
	}
	return b
}

// pixelBrightness returns the average brightness (0-255) of an RGBA pixel at offset i.
func pixelBrightness(buf []byte, i int) int {
	return (int(buf[i]) + int(buf[i+1]) + int(buf[i+2])) / 3
}

// meanBoxBrightness returns the mean pixel brightness inside box (inclusive bounds).
func meanBoxBrightness(buf []byte, w int, box changedBox) int {
	sum, count := 0, 0
	for y := box.minY; y <= box.maxY; y++ {
		for x := box.minX; x <= box.maxX; x++ {
			idx := (y*w + x) * 4
			if idx+2 >= len(buf) {
				continue
			}
			sum += pixelBrightness(buf, idx)
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / count
}

// analyzeBackdoorResponse analyzes the difference between baseline and response frames.
// It detects any new rectangular region (dark for cmd.exe, blue for PowerShell, etc.)
// that appeared after sending a trigger keystroke (5x Shift for sticky keys, Win+U for utilman).
// Returns (verdict, confidence, description).
func analyzeBackdoorResponse(baseline, response []byte, width, height uint32) (verdict string, confidence float64, description string) {
	totalPixels := int(width) * int(height)
	if totalPixels == 0 {
		return "clean", 0, "no pixels to analyze"
	}

	// Count pixels that changed significantly between baseline and response.
	// This catches any terminal window regardless of color scheme:
	// cmd.exe (black bg), PowerShell (blue bg), custom terminals, etc.
	changedPixels := 0
	for i := 0; i < totalPixels*4; i += 4 {
		if i+2 >= len(response) || i+2 >= len(baseline) {
			break
		}
		diff := pixelBrightness(baseline, i) - pixelBrightness(response, i)
		if diff < 0 {
			diff = -diff
		}
		if diff > changeThreshold {
			changedPixels++
		}
	}

	changedPercent := float64(changedPixels) / float64(totalPixels) * 100.0

	if changedPercent < minChangedPercent {
		return "clean", 0, fmt.Sprintf("%.1f%% pixels changed (below %.1f%% threshold)", changedPercent, minChangedPercent)
	}

	if changedPercent > maxChangedPercent {
		return "clean", 0, fmt.Sprintf("%.1f%% pixels changed (full screen change, not a window)", changedPercent)
	}

	// Check if changed pixels form a rectangular region (characteristic of a terminal window)
	isRect, rectScore, _ := detectChangedRectangle(baseline, response, width, height)

	if isRect && changedPercent > 3.0 {
		confidence := math.Min(0.85, changedPercent/20.0+rectScore*0.5)
		return "backdoor_likely", confidence,
			fmt.Sprintf("%.1f%% pixels changed in rectangular region (rect score: %.2f)", changedPercent, rectScore)
	}

	if changedPercent > 2.5 {
		return "backdoor_likely", 0.4,
			fmt.Sprintf("%.1f%% pixels changed (possible terminal window)", changedPercent)
	}

	return "clean", 0.1, fmt.Sprintf("%.1f%% pixels changed (minor change)", changedPercent)
}

// detectChangedRectangle checks if significantly changed pixels form a rectangular region.
// Returns (isRectangular, score, box) where score is 0-1 indicating rectangularity (fill
// ratio) and box is the bounding box of changed pixels (previously discarded).
func detectChangedRectangle(baseline, response []byte, width, height uint32) (isRectangular bool, score float64, box changedBox) {
	w := int(width)
	h := int(height)

	// Find bounding box of changed pixels
	minX, minY := w, h
	maxX, maxY := 0, 0
	changedCount := 0

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := (y*w + x) * 4
			if idx+2 >= len(response) || idx+2 >= len(baseline) {
				continue
			}
			diff := pixelBrightness(baseline, idx) - pixelBrightness(response, idx)
			if diff < 0 {
				diff = -diff
			}
			if diff > changeThreshold {
				changedCount++
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}

	if changedCount == 0 || maxX <= minX || maxY <= minY {
		return false, 0, changedBox{}
	}

	// Calculate what fraction of the bounding box is filled with changed pixels.
	// A terminal window has a solid background that fills its bounding box densely.
	boundingArea := (maxX - minX + 1) * (maxY - minY + 1)
	fillRatio := float64(changedCount) / float64(boundingArea)

	box = changedBox{
		minX:         minX,
		minY:         minY,
		maxX:         maxX,
		maxY:         maxY,
		fillRatio:    fillRatio,
		changedCount: changedCount,
	}

	// Threshold: >40% fill and at least 1% of total screen area.
	// Lowered from 60% to catch terminal windows with thin borders and sparse content.
	isRectangular = fillRatio > 0.4 && boundingArea > (w*h/100)
	return isRectangular, fillRatio, box
}

// classifyRegion inspects the changed bounding box for console-vs-dialog signals.
// It NEVER returns a verdict — only a signal that decideVerdict consults. A real console
// is large, dark, and top-left anchored; the legit accessibility dialog is small, light,
// and centered. Conjunctions (not any-of) keep it conservative.
func classifyRegion(response []byte, width, height uint32, box changedBox) regionSignal {
	w, h := int(width), int(height)
	if w == 0 || h == 0 || box.maxX <= box.minX || box.maxY <= box.minY {
		return regionUnknown
	}

	mean := meanBoxBrightness(response, w, box)
	areaFrac := float64((box.maxX-box.minX+1)*(box.maxY-box.minY+1)) / float64(w*h)
	leftFrac := float64(box.minX) / float64(w)
	topFrac := float64(box.minY) / float64(h)
	centerXFrac := float64(box.minX+box.maxX) / 2.0 / float64(w)
	centerYFrac := float64(box.minY+box.maxY) / 2.0 / float64(h)

	dark := mean <= consoleMaxMeanBrightness
	large := areaFrac >= consoleMinAreaFrac
	topLeft := leftFrac <= consoleMaxLeftFrac && topFrac <= consoleMaxTopFrac
	if dark && large && topLeft {
		return regionConsoleLike
	}

	light := mean >= dialogMinMeanBrightness
	small := areaFrac <= dialogMaxAreaFrac
	centered := centerXFrac >= dialogMinCenterFrac && centerXFrac <= 1-dialogMinCenterFrac &&
		centerYFrac >= dialogMinCenterFrac && centerYFrac <= 1-dialogMinCenterFrac
	if light && small && centered {
		return regionDialogLike
	}

	return regionUnknown
}

// decideVerdict combines the heuristic verdict, the region signal, and the behavioral
// nonce result into a final verdict. It is the single source of truth for the cardinal
// rule: no "backdoor_likely" input ever yields "clean". Pure -> unit-testable.
func decideVerdict(heuristic string, region regionSignal, nonce nonceResult) string {
	_ = region // region is informational; the cardinal rule does not depend on it.

	if heuristic != "backdoor_likely" {
		return heuristic
	}

	if nonce == nonceConfirmed {
		return "backdoor_confirmed"
	}

	// Any uncertain backdoor_likely case (unconfirmed or skipped) is honest indeterminate,
	// never clean.
	return verdictIndeterminate
}

// verifyEcho reports whether typing the nonce produced a shell-like text render inside
// the candidate box. It is a pure function over the pre-type and post-type framebuffers
// plus the box: it counts pixels whose brightness changed (same brightness-diff logic as
// analyzeBackdoorResponse) scoped to the box region, and returns nonceConfirmed when the
// changed count clears nonceMinChangedPixels (a real shell echoes the line + new prompt),
// else nonceUnconfirmed (a static dialog renders nothing new).
func verifyEcho(beforeType, afterType []byte, width, height uint32, box changedBox) nonceResult {
	w, h := int(width), int(height)
	if w == 0 || h == 0 || box.maxX <= box.minX || box.maxY <= box.minY {
		return nonceUnconfirmed
	}

	changed := 0
	for y := box.minY; y <= box.maxY; y++ {
		for x := box.minX; x <= box.maxX; x++ {
			idx := (y*w + x) * 4
			if idx+2 >= len(beforeType) || idx+2 >= len(afterType) {
				continue
			}
			diff := pixelBrightness(beforeType, idx) - pixelBrightness(afterType, idx)
			if diff < 0 {
				diff = -diff
			}
			if diff > changeThreshold {
				changed++
			}
		}
	}

	if changed >= nonceMinChangedPixels {
		return nonceConfirmed
	}
	return nonceUnconfirmed
}

// rgbaToPNG converts RGBA pixel data to a PNG byte buffer.
func rgbaToPNG(rgba []byte, width, height uint32) ([]byte, error) {
	w := int(width)
	h := int(height)

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := (y*w + x) * 4
			if idx+3 >= len(rgba) {
				break
			}
			img.SetRGBA(x, y, color.RGBA{
				R: rgba[idx],
				G: rgba[idx+1],
				B: rgba[idx+2],
				A: rgba[idx+3],
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), nil
}

// runStickyKeysAnalysis performs the dual-check: heuristic first, then Vision API if available.
func runStickyKeysAnalysis(ctx context.Context, baseline, response []byte,
	width, height uint32, visionAPIKey string, nonce nonceResult) StickyKeysResult {

	result := StickyKeysResult{Performed: true}

	// Step 1: Heuristic analysis
	verdict, confidence, description := analyzeBackdoorResponse(baseline, response, width, height)
	result.HeuristicResult = description

	if verdict == "clean" {
		result.OverallVerdict = "clean"
		result.Confidence = confidence
		return result
	}

	// Step 2: Try Vision API for confirmation if key available
	if visionAPIKey != "" {
		pngData, err := rgbaToPNG(response, width, height)
		if err == nil {
			visionVerdict, visionDesc := analyzeStickyKeysVision(ctx, pngData, visionAPIKey)
			result.VisionResult = visionDesc

			if visionVerdict == "backdoor_confirmed" {
				result.OverallVerdict = "backdoor_confirmed"
				result.Confidence = math.Min(1.0, confidence+0.3)
				return result
			}

			// If Vision says "vulnerable" (normal Ease of Access on non-NLA), respect that
			if visionVerdict == "vulnerable" {
				result.OverallVerdict = "vulnerable"
				result.Confidence = 0.8 // High confidence when Vision confirms normal behavior
				return result
			}

			if visionVerdict == "clean" && verdict == "backdoor_likely" {
				// Heuristic says backdoor, Vision says clean -- downgrade
				result.OverallVerdict = "vulnerable"
				result.Confidence = confidence * 0.5
				return result
			}
		}
	}

	// No-Vision (or inconclusive Vision) baseline: combine heuristic + pre-filter signal
	// + behavioral nonce result via the cardinal-rule decision table.
	_, _, box := detectChangedRectangle(baseline, response, width, height)
	region := classifyRegion(response, width, height, box)
	result.OverallVerdict = decideVerdict(verdict, region, nonce)
	result.Confidence = confidence
	return result
}

// runUtilmanAnalysis performs the dual-check for utilman backdoor: heuristic first, then Vision API.
func runUtilmanAnalysis(ctx context.Context, baseline, response []byte,
	width, height uint32, visionAPIKey string, nonce nonceResult) UtilmanResult {

	result := UtilmanResult{Performed: true}

	// Step 1: Heuristic analysis (same pixel diff logic as sticky keys)
	verdict, confidence, description := analyzeBackdoorResponse(baseline, response, width, height)
	result.HeuristicResult = description

	if verdict == "clean" {
		result.OverallVerdict = "clean"
		result.Confidence = confidence
		return result
	}

	// Step 2: Try Vision API for confirmation if key available
	if visionAPIKey != "" {
		pngData, err := rgbaToPNG(response, width, height)
		if err == nil {
			visionVerdict, visionDesc := analyzeUtilmanVision(ctx, pngData, visionAPIKey)
			result.VisionResult = visionDesc

			if visionVerdict == "backdoor_confirmed" {
				result.OverallVerdict = "backdoor_confirmed"
				result.Confidence = math.Min(1.0, confidence+0.3)
				return result
			}

			// If Vision says "vulnerable" (normal Ease of Access on non-NLA), respect that
			if visionVerdict == "vulnerable" {
				result.OverallVerdict = "vulnerable"
				result.Confidence = 0.8 // High confidence when Vision confirms normal behavior
				return result
			}

			if visionVerdict == "clean" && verdict == "backdoor_likely" {
				result.OverallVerdict = "vulnerable"
				result.Confidence = confidence * 0.5
				return result
			}
		}
	}

	// No-Vision (or inconclusive Vision) baseline: combine heuristic + pre-filter signal
	// + behavioral nonce result via the cardinal-rule decision table.
	_, _, box := detectChangedRectangle(baseline, response, width, height)
	region := classifyRegion(response, width, height, box)
	result.OverallVerdict = decideVerdict(verdict, region, nonce)
	result.Confidence = confidence
	return result
}
