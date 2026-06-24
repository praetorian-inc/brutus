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

	// confirmedConsoleConfidence: when a backdoor is confirmed AND the changed region
	// is console-shaped (geometry corroborates the detection), report near-certain
	// confidence. Geometry only RAISES confidence on an already-confirmed positive; it
	// never lowers a verdict (cardinal rule).
	confirmedConsoleConfidence = 0.95
)

const (
	// darkBrightnessMax: a pixel counts as "dark" when its brightness is below this.
	// Generalizes beyond pure black (#000000) so themed/blue consoles (e.g. the
	// #012456 PowerShell background, brightness ~31) still register as dark — avoiding
	// the false negatives a pure-black threshold (Sticky-Keys-Slayer) would miss.
	darkBrightnessMax = 60

	// darkDeltaCleanMaxFrac: a new-dark-pixel delta below this fraction of the screen
	// reads as clean (no console appeared — light dialog or nothing). CARDINAL RULE:
	// only a delta below this may yield "clean".
	darkDeltaCleanMaxFrac = 0.01

	// darkDeltaConsoleMinFrac / darkDeltaConsoleMaxFrac: a new-dark-pixel delta inside
	// this band reads as a console-sized dark window appearing -> backdoor_likely.
	// Below the band (small) or above it (full-screen) is ambiguous -> indeterminate.
	darkDeltaConsoleMinFrac = 0.04
	darkDeltaConsoleMaxFrac = 0.65
)

const (
	// gateConfidenceFloor: minimum analyzeBackdoorResponse confidence below which a
	// backdoor_likely needs corroborating console geometry to stay HIGH. Real consoles
	// score ~0.85; the wallpaper count-delta FP scores 0%. 0.30 sits well below real,
	// well above the FP — a margin that clips neither a full-screen nor a windowed console.
	gateConfidenceFloor = 0.30

	// gateMinDarkBoxFrac: the geometry arm's bar on how much of the changed box is an actual
	// dark console body (darkBoxFraction). Measured on ground-truth fixtures: real consoles
	// are ~0.93-0.94 dark inside the box, the dispersed wallpaper FP only ~0.35. This bar sits
	// in the gap (wide margin both ways) so a real console body passes the geometry arm while
	// a dispersed dark change does not. Replaces the synthetic-tuned fillRatio>=0.70 solidity
	// bar, which assumed real consoles fill their changed box ~1.0; they actually fill ~0.52
	// (text/cursor/scrollback differ from the baseline unevenly), so the old bar regressed
	// recall on every real console.
	gateMinDarkBoxFrac = 0.70
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

// darkPixelCount counts pixels whose brightness is below darkBrightnessMax (i.e. "dark").
func darkPixelCount(buf []byte, width, height uint32) int {
	total := int(width) * int(height)
	count := 0
	for i := 0; i < total*4; i += 4 {
		if i+2 >= len(buf) {
			break
		}
		if pixelBrightness(buf, i) < darkBrightnessMax {
			count++
		}
	}
	return count
}

// darkDeltaVerdict is the PRIMARY discriminator (Sticky-Keys-Slayer-style): it measures
// how many NEW dark pixels appeared between baseline and response. A dark console window
// appearing produces a console-sized band of new dark pixels; the legit (light)
// accessibility dialog produces almost none. CARDINAL RULE: only a near-zero delta
// (< darkDeltaCleanMaxFrac) yields "clean"; any ambiguous darkening (below the band or
// full-screen above it) is "indeterminate", never clean. Pure -> unit-testable.
func darkDeltaVerdict(baseline, response []byte, width, height uint32) string {
	total := int(width) * int(height)
	if total == 0 {
		return verdictIndeterminate
	}

	delta := darkPixelCount(response, width, height) - darkPixelCount(baseline, width, height)
	if delta < 0 {
		delta = 0
	}
	frac := float64(delta) / float64(total)

	if frac < darkDeltaCleanMaxFrac {
		return "clean"
	}
	if frac >= darkDeltaConsoleMinFrac && frac <= darkDeltaConsoleMaxFrac {
		return "backdoor_likely"
	}
	return verdictIndeterminate
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

// consoleGatePasses reports whether a backdoor_likely is backed by real console evidence
// and may therefore stay HIGH. The discriminator is CONFIDENCE: on the REAL captured frames
// the analyzeBackdoorResponse score cleanly separates a true console from the wallpaper false
// positive. Measured on ground-truth fixtures (testdata/realframes, see TestRealFrames_*):
//
//	fixture            confidence  fillRatio  areaFrac  meanBox  darkInBox  rawVerdict
//	fp_clean_utilman   0.000       0.063      0.255     81       0.349      backdoor_likely  (FP)
//	tp_cmd_sticky      0.850       0.519      0.623     24       0.930      backdoor_likely  (real)
//	tp_cmd2_sticky     0.850       0.519      0.623     24       0.930      backdoor_likely  (real)
//	tp_ps_utilman      0.850       0.506      0.623     22       0.942      backdoor_likely  (real)
//
// Confidence separates with a wide margin: FP = 0.000, every real console = 0.850, and
// gateConfidenceFloor (0.30) sits in the gap. The earlier SOLIDITY gate (fillRatio >= 0.70)
// was tuned on SYNTHETIC perfect rectangles whose changed box fills ~1.0; REAL consoles only
// fill ~0.52 of their changed box (text/scrollback/cursor differ from the gray-ish baseline
// unevenly), so the old "dispersed dark" exclusion mis-flagged every real console as a non-
// console and downgraded it. That solidity assumption is removed.
//
// Two arms keep HIGH:
//   - Geometry arm: a dark, large, top-left-or-not rectangle whose box is mostly dark pixels
//     (darkInBox) is a real console body regardless of confidence. This is a confidence-
//     independent fast path; it uses the box's actual dark density (FP 0.349 vs real ~0.93),
//     not fillRatio-vs-baseline. Position is deliberately dropped so a windowed/centered
//     console still passes (recall).
//   - Confidence arm: the analyzeBackdoorResponse score reaches the real-console range
//     (>= gateConfidenceFloor). The wallpaper FP scores 0.000, far below the floor.
//
// Pure -> unit-testable.
func consoleGatePasses(response []byte, width, height uint32, box changedBox, confidence float64) bool {
	w, h := int(width), int(height)
	if w == 0 || h == 0 || box.maxX <= box.minX || box.maxY <= box.minY {
		return false
	}

	mean := meanBoxBrightness(response, w, box)
	areaFrac := float64((box.maxX-box.minX+1)*(box.maxY-box.minY+1)) / float64(w*h)
	dark := mean <= consoleMaxMeanBrightness
	large := areaFrac >= consoleMinAreaFrac

	// Geometry arm: a dark, large box that is itself mostly dark pixels is a real console
	// body regardless of confidence or position. darkInBox is the fraction of the bounding
	// box that is actually dark — on real consoles ~0.93, on the dispersed wallpaper FP
	// ~0.35 — a far better "is this a console body" signal than fillRatio (changed-vs-baseline).
	if dark && large && darkBoxFraction(response, w, box) >= gateMinDarkBoxFrac {
		return true
	}

	// Confidence arm: the analyzeBackdoorResponse score reaches the real-console range.
	return confidence >= gateConfidenceFloor
}

// darkBoxFraction returns the fraction of pixels inside box whose brightness is below
// darkBrightnessMax. Unlike changedBox.fillRatio (which measures how much of the box DIFFERS
// from the baseline), this measures how much of the box is an actual dark console body — the
// signal that cleanly separates a real console (~0.93) from a dispersed wallpaper shift (~0.35).
func darkBoxFraction(buf []byte, w int, box changedBox) float64 {
	darkCount, count := 0, 0
	for y := box.minY; y <= box.maxY; y++ {
		for x := box.minX; x <= box.maxX; x++ {
			idx := (y*w + x) * 4
			if idx+2 >= len(buf) {
				continue
			}
			if pixelBrightness(buf, idx) < darkBrightnessMax {
				darkCount++
			}
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return float64(darkCount) / float64(count)
}

// decideVerdict gates the dark-delta verdict against console evidence. When keepHigh is
// false it downgrades a backdoor_likely (a no-console count artifact) to indeterminate;
// every other verdict — backdoor_confirmed, vulnerable, clean, indeterminate — passes
// through untouched. CARDINAL RULE: it NEVER maps any verdict to "clean", and a confirmed
// positive is never downgraded. keepHigh is computed by consoleGatePasses at the call site.
// Pure -> unit-testable.
func decideVerdict(verdict string, keepHigh bool) string {
	if verdict == "backdoor_likely" && !keepHigh {
		return verdictIndeterminate
	}
	return verdict
}

// regionConfidenceAndNote enriches an already-decided verdict with the geometry signal.
// It NEVER changes the verdict (cardinal rule) — it only (a) raises confidence when a
// confirmed backdoor is also console-shaped, and (b) returns an operator-facing note so
// the banner explains what the geometry showed. Echo always beats geometry: a
// dialog-shaped or unknown-shaped region that is still behaviorally confirmed stays
// confirmed; the note just records the (non-corroborating) geometry. For an unconfirmed
// (indeterminate) verdict the note tells the operator what to expect on a rerun.
// Pure -> unit-testable; baseConfidence is returned unchanged unless a boost applies.
func regionConfidenceAndNote(verdict string, region regionSignal, baseConfidence float64) (confidence float64, note string) {
	switch verdict {
	case "backdoor_confirmed":
		switch region {
		case regionConsoleLike:
			return confirmedConsoleConfidence, "console-shaped + dark-region confirmed"
		case regionDialogLike:
			return baseConfidence, "dialog-shaped but dark-region confirmed (dark-delta beats geometry)"
		default:
			return baseConfidence, "geometry inconclusive but dark-region confirmed (dark-delta beats geometry)"
		}
	case verdictIndeterminate:
		switch region {
		case regionConsoleLike:
			return baseConfidence, "console-shaped, unconfirmed — rerun"
		case regionDialogLike:
			return baseConfidence, "dialog-shaped, unconfirmed — rerun"
		default:
			return baseConfidence, "geometry inconclusive, unconfirmed — rerun"
		}
	default:
		return baseConfidence, ""
	}
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

// runStickyKeysAnalysis performs the dual-check: dark-delta heuristic first, then Vision
// API if available. The dark-pixel-delta discriminator is the primary heuristic (it
// distinguishes the dark cmd console from the light legit dialog); Vision still wins when
// present (confirmed/vulnerable branches sit above the heuristic verdict).
func runStickyKeysAnalysis(ctx context.Context, baseline, response []byte,
	width, height uint32, visionAPIKey string) StickyKeysResult {

	result := StickyKeysResult{Performed: true}

	// Step 1: Primary heuristic — dark-pixel-delta discriminator. The changed-pixels
	// description is kept for the diagnostic banner; the VERDICT comes from darkDeltaVerdict.
	verdict := darkDeltaVerdict(baseline, response, width, height)
	_, confidence, description := analyzeBackdoorResponse(baseline, response, width, height)
	result.HeuristicResult = description

	if verdict == "clean" {
		result.OverallVerdict = "clean"
		result.Confidence = confidence
		return result
	}

	// Step 2: Try Vision API for confirmation if key available (Vision wins when present).
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

	// No-Vision (or inconclusive Vision) baseline: pass the dark-delta verdict through
	// decideVerdict (cardinal rule — a positive never becomes clean). The region signal
	// never changes the verdict; it only enriches confidence and the diagnostic banner
	// via regionConfidenceAndNote.
	_, _, box := detectChangedRectangle(baseline, response, width, height)
	region := classifyRegion(response, width, height, box)
	keepHigh := consoleGatePasses(response, width, height, box, confidence)
	result.OverallVerdict = decideVerdict(verdict, keepHigh)
	result.Confidence, result.RegionNote = regionConfidenceAndNote(result.OverallVerdict, region, confidence)
	return result
}

// runUtilmanAnalysis performs the dual-check for utilman backdoor: dark-delta heuristic
// first, then Vision API. Same wiring as runStickyKeysAnalysis.
func runUtilmanAnalysis(ctx context.Context, baseline, response []byte,
	width, height uint32, visionAPIKey string) UtilmanResult {

	result := UtilmanResult{Performed: true}

	// Step 1: Primary heuristic — dark-pixel-delta discriminator. The changed-pixels
	// description is kept for the diagnostic banner; the VERDICT comes from darkDeltaVerdict.
	verdict := darkDeltaVerdict(baseline, response, width, height)
	_, confidence, description := analyzeBackdoorResponse(baseline, response, width, height)
	result.HeuristicResult = description

	if verdict == "clean" {
		result.OverallVerdict = "clean"
		result.Confidence = confidence
		return result
	}

	// Step 2: Try Vision API for confirmation if key available (Vision wins when present).
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

	// No-Vision (or inconclusive Vision) baseline: pass the dark-delta verdict through
	// decideVerdict (cardinal rule — a positive never becomes clean). The region signal
	// never changes the verdict; it only enriches confidence and the diagnostic banner
	// via regionConfidenceAndNote.
	_, _, box := detectChangedRectangle(baseline, response, width, height)
	region := classifyRegion(response, width, height, box)
	keepHigh := consoleGatePasses(response, width, height, box, confidence)
	result.OverallVerdict = decideVerdict(verdict, keepHigh)
	result.Confidence, result.RegionNote = regionConfidenceAndNote(result.OverallVerdict, region, confidence)
	return result
}
