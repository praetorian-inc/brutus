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
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeStickyKeysResponse_Clean(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4

	// Both frames identical (light gray)
	baseline := make([]byte, size)
	response := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 128
		baseline[i+1] = 128
		baseline[i+2] = 128
		baseline[i+3] = 255
		response[i] = 128
		response[i+1] = 128
		response[i+2] = 128
		response[i+3] = 255
	}

	verdict, confidence, _ := analyzeBackdoorResponse(baseline, response, w, h)
	assert.Equal(t, "clean", verdict)
	assert.LessOrEqual(t, confidence, 0.5)
}

func TestAnalyzeStickyKeysResponse_DarkRectangle(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4

	// Baseline: all light gray
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 128
		baseline[i+1] = 128
		baseline[i+2] = 128
		baseline[i+3] = 255
	}

	// Response: dark rectangle in center (simulating cmd.exe window)
	response := make([]byte, size)
	copy(response, baseline)
	for y := 20; y < 80; y++ {
		for x := 20; x < 80; x++ {
			idx := (y*int(w) + x) * 4
			response[idx] = 0     // R
			response[idx+1] = 0   // G
			response[idx+2] = 0   // B
			response[idx+3] = 255 // A
		}
	}

	verdict, confidence, _ := analyzeBackdoorResponse(baseline, response, w, h)
	assert.Contains(t, []string{"backdoor_likely", "vulnerable"}, verdict)
	assert.Greater(t, confidence, 0.0)
}

func TestBitmapDiff(t *testing.T) {
	w, h := uint32(10), uint32(10)
	size := int(w) * int(h) * 4

	a := make([]byte, size)
	b := make([]byte, size)

	// Set first pixel different
	a[0] = 100
	b[0] = 200

	diff := bitmapDiff(a, b, w, h)
	assert.NotNil(t, diff)
	assert.Equal(t, byte(100), diff[0]) // |200-100| = 100
}

func TestAnalyzeBackdoorResponse_FullScreenChange(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4

	// Baseline: all white
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 255
		baseline[i+1] = 255
		baseline[i+2] = 255
		baseline[i+3] = 255
	}

	// Response: all black (>80% change = full screen change, not a window)
	response := make([]byte, size)
	for i := 0; i < size; i += 4 {
		response[i] = 0
		response[i+1] = 0
		response[i+2] = 0
		response[i+3] = 255
	}

	verdict, _, desc := analyzeBackdoorResponse(baseline, response, w, h)
	assert.Equal(t, "clean", verdict)
	assert.Contains(t, desc, "full screen change")
}

func TestAnalyzeBackdoorResponse_ZeroPixels(t *testing.T) {
	verdict, confidence, desc := analyzeBackdoorResponse(nil, nil, 0, 0)
	assert.Equal(t, "clean", verdict)
	assert.Equal(t, 0.0, confidence)
	assert.Contains(t, desc, "no pixels")
}

func TestRunUtilmanAnalysis_Clean(t *testing.T) {
	w, h := uint32(50), uint32(50)
	size := int(w) * int(h) * 4

	// Identical frames
	baseline := make([]byte, size)
	response := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 100
		baseline[i+1] = 100
		baseline[i+2] = 100
		baseline[i+3] = 255
		response[i] = 100
		response[i+1] = 100
		response[i+2] = 100
		response[i+3] = 255
	}

	ctx := context.Background()
	result := runUtilmanAnalysis(ctx, baseline, response, w, h, "")
	assert.True(t, result.Performed)
	assert.Equal(t, "clean", result.OverallVerdict)
}

func TestRgbaToPNG(t *testing.T) {
	w, h := uint32(2), uint32(2)
	rgba := make([]byte, 16) // 2x2x4
	for i := range rgba {
		rgba[i] = 128
	}

	pngData, err := rgbaToPNG(rgba, w, h)
	assert.NoError(t, err)
	assert.True(t, len(pngData) > 0)
	// PNG magic bytes
	assert.Equal(t, byte(0x89), pngData[0])
	assert.Equal(t, byte(0x50), pngData[1])
}

// ---------------------------------------------------------------------------
// A1: detectChangedRectangle returns bounding box
// ---------------------------------------------------------------------------

func TestDetectChangedRectangle_ReturnsBox(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i], baseline[i+1], baseline[i+2], baseline[i+3] = 128, 128, 128, 255
	}
	response := make([]byte, size)
	copy(response, baseline)
	// dark rect [20,80)x[20,80)
	for y := 20; y < 80; y++ {
		for x := 20; x < 80; x++ {
			idx := (y*int(w) + x) * 4
			response[idx], response[idx+1], response[idx+2], response[idx+3] = 0, 0, 0, 255
		}
	}
	_, _, box := detectChangedRectangle(baseline, response, w, h)
	assert.Equal(t, 20, box.minX)
	assert.Equal(t, 20, box.minY)
	assert.Equal(t, 79, box.maxX)
	assert.Equal(t, 79, box.maxY)
	assert.Greater(t, box.changedCount, 0)
}

// ---------------------------------------------------------------------------
// A2: classifyRegion — console vs dialog vs unknown discrimination
// ---------------------------------------------------------------------------

// paintBox fills a rectangular region of an RGBA buffer with the given gray value.
func paintBox(buf []byte, w, x0, y0, x1, y1 int, gray byte) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			idx := (y*w + x) * 4
			buf[idx], buf[idx+1], buf[idx+2], buf[idx+3] = gray, gray, gray, 255
		}
	}
}

// paintBoxRGB fills a rectangular region with explicit RGB values.
// Used for themed-console tests (e.g. PowerShell blue, brightness ~31).
func paintBoxRGB(buf []byte, w, x0, y0, x1, y1 int, r, g, b byte) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			idx := (y*w + x) * 4
			buf[idx], buf[idx+1], buf[idx+2], buf[idx+3] = r, g, b, 255
		}
	}
}

func TestClassifyRegion_ConsoleLike(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	resp := make([]byte, int(w)*int(h)*4)
	// large dark box anchored top-left: [0,0)x[600,600), gray 0
	paintBox(resp, int(w), 0, 0, 600, 600, 0)
	box := changedBox{minX: 0, minY: 0, maxX: 599, maxY: 599, changedCount: 600 * 600}
	assert.Equal(t, regionConsoleLike, classifyRegion(resp, w, h, box))
}

func TestClassifyRegion_DialogLike(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	resp := make([]byte, int(w)*int(h)*4)
	// small light box centered: [430,430)x[570,570), gray 200
	paintBox(resp, int(w), 430, 430, 570, 570, 200)
	box := changedBox{minX: 430, minY: 430, maxX: 569, maxY: 569, changedCount: 140 * 140}
	assert.Equal(t, regionDialogLike, classifyRegion(resp, w, h, box))
}

func TestClassifyRegion_Unknown(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	resp := make([]byte, int(w)*int(h)*4)
	// medium mid-gray box, neither corner-anchored nor centered-small
	paintBox(resp, int(w), 200, 100, 500, 400, 110)
	box := changedBox{minX: 200, minY: 100, maxX: 499, maxY: 399, changedCount: 300 * 300}
	assert.Equal(t, regionUnknown, classifyRegion(resp, w, h, box))
}

// ---------------------------------------------------------------------------
// A3: decideVerdict — gates backdoor_likely on keepHigh boolean
// Signature: decideVerdict(verdict string, keepHigh bool) string
// When keepHigh=false a backdoor_likely is downgraded to indeterminate.
// All other verdicts pass through unchanged.
// CARDINAL RULE: backdoor_likely with keepHigh=false → indeterminate, NEVER clean.
// ---------------------------------------------------------------------------

func TestDecideVerdict(t *testing.T) {
	tests := []struct {
		name     string
		verdict  string
		keepHigh bool
		want     string
	}{
		// Real console — keepHigh=true → kept as backdoor_likely.
		{"backdoor_likely keepHigh=true → backdoor_likely", "backdoor_likely", true, "backdoor_likely"},
		// No-console count artifact — keepHigh=false → downgraded to indeterminate.
		{"backdoor_likely keepHigh=false → indeterminate", "backdoor_likely", false, verdictIndeterminate},
		// Gate never touches clean.
		{"clean keepHigh=false → clean", "clean", false, "clean"},
		{"clean keepHigh=true → clean", "clean", true, "clean"},
		// Gate never touches indeterminate.
		{"indeterminate keepHigh=false → indeterminate", verdictIndeterminate, false, verdictIndeterminate},
		// Vision positives (backdoor_confirmed, vulnerable) are never downgraded.
		{"backdoor_confirmed keepHigh=false → backdoor_confirmed", "backdoor_confirmed", false, "backdoor_confirmed"},
		{"vulnerable keepHigh=false → vulnerable", "vulnerable", false, "vulnerable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decideVerdict(tc.verdict, tc.keepHigh)
			assert.Equal(t, tc.want, got)
			// CARDINAL RULE: backdoor_likely with keepHigh=false must yield indeterminate,
			// never clean.
			if tc.verdict == "backdoor_likely" && !tc.keepHigh {
				assert.NotEqual(t, "clean", got,
					"CARDINAL RULE: backdoor_likely downgrade target is indeterminate, never clean")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A6: consoleGatePasses — pure predicate unit table
// Signature: consoleGatePasses(response []byte, width, height uint32, box changedBox, confidence float64) bool
// Tests cover: FP fragmented shift, full-screen console, windowed console,
// confidence-floor path, floor boundary, below-floor non-rect, degenerate box.
// ---------------------------------------------------------------------------

func TestConsoleGatePasses(t *testing.T) {
	const W, H = uint32(1024), uint32(768)
	totalPx := int(W) * int(H)

	// newResp builds a uniform gray response frame.
	newResp := func(gray byte) []byte {
		buf := make([]byte, totalPx*4)
		for i := 0; i < len(buf); i += 4 {
			buf[i], buf[i+1], buf[i+2], buf[i+3] = gray, gray, gray, 255
		}
		return buf
	}

	tests := []struct {
		name       string
		buildResp  func() []byte
		box        changedBox
		confidence float64
		want       bool
	}{
		{
			// FP: fragmented shift — sparse changed pixels, non-dense box → fillRatio=0.2
			// darkness doesn't matter because fillRatio fails the rect check.
			name: "FP fragmented shift: fillRatio=0.2 confidence=0 → false",
			buildResp: func() []byte {
				r := newResp(0) // dark response so mean passes
				return r
			},
			// box: 200×200 at origin, fillRatio=0.2 (sparse) — area=3.2%, dark
			box:        changedBox{minX: 0, minY: 0, maxX: 199, maxY: 199, fillRatio: 0.20, changedCount: 8000},
			confidence: 0.0,
			want:       false,
		},
		{
			// Full-screen console: dark, large (≥18% area), dense fill.
			// box: 560×560 = 313600/786432 ≈ 39.9% area; fillRatio=0.95
			name: "full-screen console: dark large rect → true (geometry)",
			buildResp: func() []byte {
				r := newResp(128) // mid-gray frame
				paintBox(r, int(W), 0, 0, 560, 560, 0)
				return r
			},
			box:        changedBox{minX: 0, minY: 0, maxX: 559, maxY: 559, fillRatio: 0.95, changedCount: 560 * 560},
			confidence: 0.0,
			want:       true,
		},
		{
			// Windowed console: centered, NOT top-left anchored (leftFrac≈0.39, topFrac≈0.39).
			// classifyRegion would return regionUnknown because topLeft fails,
			// but consoleGatePasses must still return true (position is irrelevant to the gate).
			// box: 400×400 at (400,300) → area=400*400/786432≈20.3%; fillRatio=0.9
			name: "windowed console centered NOT top-left: dark large rect → true (position irrelevant)",
			buildResp: func() []byte {
				r := newResp(128)
				paintBox(r, int(W), 400, 300, 800, 700, 0)
				return r
			},
			box:        changedBox{minX: 400, minY: 300, maxX: 799, maxY: 699, fillRatio: 0.90, changedCount: 400 * 400},
			confidence: 0.0,
			want:       true,
		},
		{
			// Confidence-floor path: box is non-rectangular (fillRatio=0.1) but
			// confidence=0.85 exceeds gateConfidenceFloor(0.30) → true via floor.
			name: "non-rect box but confidence=0.85 ≥ floor → true (floor path)",
			buildResp: func() []byte {
				return newResp(128)
			},
			box:        changedBox{minX: 100, minY: 100, maxX: 299, maxY: 299, fillRatio: 0.10, changedCount: 4000},
			confidence: 0.85,
			want:       true,
		},
		{
			// Floor boundary: confidence exactly at gateConfidenceFloor (0.30) → true (>=).
			name: "non-rect box, confidence exactly at floor=0.30 → true",
			buildResp: func() []byte {
				return newResp(128)
			},
			box:        changedBox{minX: 100, minY: 100, maxX: 299, maxY: 299, fillRatio: 0.10, changedCount: 4000},
			confidence: gateConfidenceFloor,
			want:       true,
		},
		{
			// Just below floor: confidence=0.29 AND non-rect (fillRatio=0.1) → false.
			name: "non-rect box, confidence=0.29 just below floor → false",
			buildResp: func() []byte {
				return newResp(128)
			},
			box:        changedBox{minX: 100, minY: 100, maxX: 299, maxY: 299, fillRatio: 0.10, changedCount: 4000},
			confidence: 0.29,
			want:       false,
		},
		{
			// Degenerate box (maxX <= minX): always false regardless of confidence.
			name: "degenerate box maxX<=minX → false",
			buildResp: func() []byte {
				return newResp(0)
			},
			box:        changedBox{minX: 100, minY: 100, maxX: 100, maxY: 200, fillRatio: 0.0, changedCount: 0},
			confidence: 0.0,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.buildResp()
			got := consoleGatePasses(resp, W, H, tc.box, tc.confidence)
			assert.Equal(t, tc.want, got,
				"consoleGatePasses(box=%+v, confidence=%.2f)", tc.box, tc.confidence)
		})
	}
}

// ---------------------------------------------------------------------------
// A7: TestConsoleGate_EndToEnd — end-to-end frame→verdict gate behavior
// Drives runUtilmanAnalysis and runStickyKeysAnalysis on 1024×768 RGBA frames.
// No WASM, no network. Baseline = uniform mid-gray 128.
// ---------------------------------------------------------------------------

func TestConsoleGate_EndToEnd(t *testing.T) {
	const W, H = uint32(1024), uint32(768)
	totalPx := int(W) * int(H)

	// Build a uniform mid-gray (128) baseline.
	baseline := make([]byte, totalPx*4)
	for i := 0; i < len(baseline); i += 4 {
		baseline[i], baseline[i+1], baseline[i+2], baseline[i+3] = 128, 128, 128, 255
	}

	newResponse := func() []byte {
		r := make([]byte, totalPx*4)
		copy(r, baseline)
		return r
	}

	// runBoth drives the same frame through both analysis functions and returns
	// (stickyVerdict, utilmanVerdict) so a single assertion loop covers both.
	runBoth := func(response []byte) (string, string) {
		ctx := context.Background()
		sticky := runStickyKeysAnalysis(ctx, baseline, response, W, H, "")
		utilman := runUtilmanAnalysis(ctx, baseline, response, W, H, "")
		return sticky.OverallVerdict, utilman.OverallVerdict
	}

	t.Run("FP_regression: dispersed dark change fails the geometry arm (real FP covered by realframes fixture)", func(t *testing.T) {
		// The genuine end-to-end wallpaper false positive is asserted against GROUND TRUTH by
		// TestRealFrames_GateRegression/fp_clean_utilman (real capture: confidence ~0.000,
		// darkBoxFraction ~0.35 → downgraded to indeterminate). That is the authoritative FP test.
		//
		// A SYNTHETIC checkerboard cannot honestly reproduce that FP: to put the dark-pixel COUNT
		// delta inside the console band [0.04, 0.65] it must change >4% of pixels, and
		// analyzeBackdoorResponse scores ANY >2.5%-changed non-rectangular frame at 0.4 confidence
		// (its fixed "possible terminal window" fallback) — above gateConfidenceFloor(0.30). The
		// old synthetic FP only "worked" because it painted a dense every-other-pixel band that the
		// removed solidity veto happened to reject; that band was UNREALISTIC (the real FP is thinly
		// dark, not near-solid) and forcing it to downgrade is exactly the over-aggressive gate that
		// regressed real consoles. So here we assert the honest, non-overfit property: a dispersed
		// dark change whose bounding box is only thinly dark FAILS the geometry arm (it is not a
		// console body), which is the arm this synthetic exercises.
		resp := newResponse()
		// Paint 1 dark pixel out of every 16, spread over the whole frame: maximally dispersed,
		// box spans the screen, but darkBoxFraction is tiny.
		for y := 0; y < int(H); y += 4 {
			for x := 0; x < int(W); x += 4 {
				idx := (y*int(W) + x) * 4
				resp[idx], resp[idx+1], resp[idx+2], resp[idx+3] = 0, 0, 0, 255
			}
		}

		_, _, box := detectChangedRectangle(baseline, resp, W, H)
		darkFrac := darkBoxFraction(resp, int(W), box)
		assert.Less(t, darkFrac, gateMinDarkBoxFrac,
			"dispersed dark change must have a thinly-dark box (darkBoxFraction %.3f) below the geometry bar", darkFrac)
		// Geometry arm alone must NOT keep this HIGH (confidence=0 isolates the geometry path).
		assert.False(t, consoleGatePasses(resp, W, H, box, 0.0),
			"dispersed dark change with no confidence must NOT pass the gate via geometry")
	})

	t.Run("recall_full_screen_console: large dark rect top-left → backdoor_likely", func(t *testing.T) {
		// Full-screen black console rectangle anchored top-left: ~40% area, solid.
		// paintBox(resp, 1024, 0, 0, 560, 560, 0) → 560×560/786432 ≈ 39.9%
		resp := newResponse()
		paintBox(resp, int(W), 0, 0, 560, 560, 0)

		stickyV, utilmanV := runBoth(resp)
		assert.Equal(t, "backdoor_likely", stickyV,
			"full-screen console (sticky) must stay backdoor_likely")
		assert.Equal(t, "backdoor_likely", utilmanV,
			"full-screen console (utilman) must stay backdoor_likely")
	})

	t.Run("recall_windowed_console: centered NOT top-left dark rect → backdoor_likely", func(t *testing.T) {
		// Windowed console centered at (400,250)→(850,700): ~28% area, solid black.
		// leftFrac=400/1024≈0.39 and topFrac=250/768≈0.33 — both exceed
		// consoleMaxLeftFrac/consoleMaxTopFrac(0.25), so classifyRegion returns
		// regionUnknown. The gate must still pass it via the geometry path
		// (dark+large+rect, WITHOUT the position constraint).
		resp := newResponse()
		paintBox(resp, int(W), 400, 250, 850, 700, 0)

		stickyV, utilmanV := runBoth(resp)
		assert.Equal(t, "backdoor_likely", stickyV,
			"windowed console (sticky) must stay backdoor_likely — gate must NOT require top-left anchoring")
		assert.Equal(t, "backdoor_likely", utilmanV,
			"windowed console (utilman) must stay backdoor_likely — gate must NOT require top-left anchoring")
	})

	t.Run("recall_themed_console: blue-ish dark windowed console → backdoor_likely", func(t *testing.T) {
		// PowerShell-style console: RGB=(1,36,86), brightness=(1+36+86)/3=41 < darkBrightnessMax(60).
		// Same position as windowed console test; centered, NOT top-left.
		resp := newResponse()
		paintBoxRGB(resp, int(W), 400, 250, 850, 700, 1, 36, 86)

		stickyV, utilmanV := runBoth(resp)
		assert.Equal(t, "backdoor_likely", stickyV,
			"themed windowed console (sticky) must stay backdoor_likely")
		assert.Equal(t, "backdoor_likely", utilmanV,
			"themed windowed console (utilman) must stay backdoor_likely")
	})

	t.Run("unchanged_behavior: light dialog → clean", func(t *testing.T) {
		// Light small centered dialog (gray 200) adds almost no dark pixels → clean.
		// Mirrors existing TestRunStickyKeysAnalysis_LightDialog_NoVision_Clean.
		resp := newResponse()
		paintBox(resp, int(W), 440, 280, 580, 480, 200)

		stickyV, utilmanV := runBoth(resp)
		assert.Equal(t, "clean", stickyV,
			"light dialog (sticky) must remain clean")
		assert.Equal(t, "clean", utilmanV,
			"light dialog (utilman) must remain clean")
	})
}

// ---------------------------------------------------------------------------
// A4: runStickyKeysAnalysis — light/small/centered dialog → clean
// A light legit dialog (gray 200) adds almost no dark pixels, so the
// dark-delta discriminator correctly returns "clean", not indeterminate.
// This is the better outcome vs. the old behavioral approach.
// ---------------------------------------------------------------------------

func TestRunStickyKeysAnalysis_LightDialog_NoVision_Clean(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	size := int(w) * int(h) * 4
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i], baseline[i+1], baseline[i+2], baseline[i+3] = 128, 128, 128, 255
	}
	response := make([]byte, size)
	copy(response, baseline)
	// Light small centered dialog (220×220 = 4.84% area, gray 200).
	// Gray 200 >> darkBrightnessMax(60), so adds zero dark pixels → clean.
	paintBox(response, int(w), 390, 390, 610, 610, 200)
	res := runStickyKeysAnalysis(context.Background(), baseline, response, w, h, "")
	assert.Equal(t, "clean", res.OverallVerdict)
	assert.NotEqual(t, "backdoor_likely", res.OverallVerdict,
		"a light legit dialog must not be flagged as backdoor_likely")
}

// ---------------------------------------------------------------------------
// B: dark-pixel-delta core logic — new tests for the primary discriminator
// ---------------------------------------------------------------------------

// TestDarkPixelCount verifies the count of pixels below darkBrightnessMax.
func TestDarkPixelCount(t *testing.T) {
	w, h := uint32(10), uint32(10) // 100 pixels
	size := int(w) * int(h) * 4
	buf := make([]byte, size)

	// Fill all pixels with mid-gray (brightness 128, well above threshold 60).
	for i := 0; i < size; i += 4 {
		buf[i], buf[i+1], buf[i+2], buf[i+3] = 128, 128, 128, 255
	}
	assert.Equal(t, 0, darkPixelCount(buf, w, h), "mid-gray pixels should not count as dark")

	// Paint a 5×5 block with pure black (brightness 0 < 60).
	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			idx := (y*int(w) + x) * 4
			buf[idx], buf[idx+1], buf[idx+2], buf[idx+3] = 0, 0, 0, 255
		}
	}
	assert.Equal(t, 25, darkPixelCount(buf, w, h), "5×5 black block must count as 25 dark pixels")

	// Paint 3 more pixels with brightness exactly at the threshold (60 is NOT dark; must be < 60).
	// brightness = (59+59+59)/3 = 59 < 60 → dark.
	buf[100], buf[101], buf[102] = 59, 59, 59 // pixel at offset 100 (pixel 25)
	assert.Equal(t, 26, darkPixelCount(buf, w, h), "pixel with brightness 59 must count as dark")

	// A pixel with brightness exactly 60 is NOT dark (threshold is strict <).
	buf[104], buf[105], buf[106] = 60, 60, 60 // pixel 26
	assert.Equal(t, 26, darkPixelCount(buf, w, h), "pixel with brightness exactly 60 must NOT count as dark")
}

// TestDarkDeltaVerdict exercises the primary discriminator end-to-end with 1000×1000 frames.
// Baseline is mid-gray (128) everywhere; the response adds various shapes.
func TestDarkDeltaVerdict(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	size := int(w) * int(h) * 4

	// Construct a reusable mid-gray baseline.
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i], baseline[i+1], baseline[i+2], baseline[i+3] = 128, 128, 128, 255
	}

	newResponse := func() []byte {
		r := make([]byte, size)
		copy(r, baseline)
		return r
	}

	tests := []struct {
		name    string
		setup   func(response []byte)
		want    string
		notWant string // optional cardinal-rule guard
	}{
		{
			// Large dark box (gray 0) covering ~30% of the screen → backdoor_likely.
			// 548×548 pixels = ~30% of 1000×1000.  Fraction is in [0.04, 0.65].
			name: "large dark box (~30%) → backdoor_likely",
			setup: func(r []byte) {
				paintBox(r, int(w), 0, 0, 548, 548, 0)
			},
			want:    "backdoor_likely",
			notWant: "clean",
		},
		{
			// Light dialog box (gray 200, small) → no new dark pixels → clean.
			// Gray 200 >> darkBrightnessMax(60); delta ≈ 0 < 1%.
			name: "light dialog box (gray 200, small) → clean",
			setup: func(r []byte) {
				paintBox(r, int(w), 430, 430, 570, 570, 200)
			},
			want: "clean",
		},
		{
			// Tiny dark box (~2% area, gray 0) → below console band → indeterminate.
			// 140×140 = 19600 pixels / 1000000 = 1.96% → in (1%, 4%) → indeterminate.
			name: "tiny dark box (~2%) → indeterminate",
			setup: func(r []byte) {
				paintBox(r, int(w), 0, 0, 140, 140, 0)
			},
			want:    verdictIndeterminate,
			notWant: "clean",
		},
		{
			// Near-full-screen dark (>65%, gray 0) → above console band → indeterminate.
			// 820×820 = 672400 / 1000000 = 67.24% > 65%.
			name: "near-full-screen dark (>65%) → indeterminate",
			setup: func(r []byte) {
				paintBox(r, int(w), 0, 0, 820, 820, 0)
			},
			want:    verdictIndeterminate,
			notWant: "clean",
		},
		{
			// Themed/blue-ish dark console (RGB ≈ (1,36,86), brightness ≈ 41 < 60).
			// Still registers as dark → ~30% area → backdoor_likely.
			// brightness = (1 + 36 + 86) / 3 = 123/3 = 41 < darkBrightnessMax(60).
			name: "blue-ish dark console (~30%) → backdoor_likely",
			setup: func(r []byte) {
				paintBoxRGB(r, int(w), 0, 0, 548, 548, 1, 36, 86)
			},
			want:    "backdoor_likely",
			notWant: "clean",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := newResponse()
			tc.setup(response)
			got := darkDeltaVerdict(baseline, response, w, h)
			assert.Equal(t, tc.want, got)
			if tc.notWant != "" {
				assert.NotEqual(t, tc.notWant, got,
					"CARDINAL RULE: dark/ambiguous box must never yield %q", tc.notWant)
			}
		})
	}

	// CARDINAL SUB-ASSERT: for any dark box of console-band size, result is never "clean".
	t.Run("cardinal_rule_dark_box_never_clean", func(t *testing.T) {
		// Try several in-band sizes and confirm none yield "clean".
		inBandSizes := []int{210, 300, 400, 500, 600, 700} // pixel edge lengths
		for _, edge := range inBandSizes {
			frac := float64(edge*edge) / float64(int(w)*int(h))
			if frac < darkDeltaConsoleMinFrac || frac > darkDeltaConsoleMaxFrac {
				continue // skip if this particular size fell outside the band
			}
			response := newResponse()
			paintBox(response, int(w), 0, 0, edge, edge, 0)
			got := darkDeltaVerdict(baseline, response, w, h)
			assert.NotEqual(t, "clean", got,
				"dark box of edge %d (frac %.3f) must not yield clean", edge, frac)
		}
	})
}

// ---------------------------------------------------------------------------
// C1: structural guard — runStickyKeysAnalysis must have the vulnerable branch
// ---------------------------------------------------------------------------

// TestRunStickyKeysAnalysis_HasVulnerableBranch guards that runStickyKeysAnalysis
// contains a symmetric `visionVerdict == "vulnerable"` branch matching the one
// already present in runUtilmanAnalysis (analyze.go ~line 456).
// The test reads analyze.go as source text and asserts the string
// `visionVerdict == "vulnerable"` appears at least twice — once per analysis
// function. Currently it appears only once (utilman only), so this test is RED
// until the developer adds the symmetric branch to runStickyKeysAnalysis.
func TestRunStickyKeysAnalysis_HasVulnerableBranch(t *testing.T) {
	src, err := os.ReadFile("analyze.go")
	require.NoError(t, err, "analyze.go must be readable")

	const needle = `visionVerdict == "vulnerable"`
	count := strings.Count(string(src), needle)
	assert.GreaterOrEqual(t, count, 2,
		"runStickyKeysAnalysis is missing the visionVerdict == \"vulnerable\" branch; "+
			"found %d occurrence(s), need >= 2 (one per analysis function)", count)
}

// ---------------------------------------------------------------------------
// A5: regionConfidenceAndNote — pure verdict×region → (confidence, note)
// ---------------------------------------------------------------------------

func TestRegionConfidenceAndNote(t *testing.T) {
	const base = 0.75

	tests := []struct {
		name           string
		verdict        string
		region         regionSignal
		base           float64
		wantConfidence float64
		wantNote       string
	}{
		// backdoor_confirmed + console-shaped: geometry corroborates → high confidence boost
		{
			name:           "confirmed + console → high confidence + console note",
			verdict:        "backdoor_confirmed",
			region:         regionConsoleLike,
			base:           base,
			wantConfidence: confirmedConsoleConfidence,
			wantNote:       "console-shaped + dark-region confirmed",
		},
		// backdoor_confirmed + dialog-shaped: dark-delta beats geometry → base confidence unchanged
		{
			name:           "confirmed + dialog → base confidence + dark-delta-beats-geometry note",
			verdict:        "backdoor_confirmed",
			region:         regionDialogLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "dialog-shaped but dark-region confirmed (dark-delta beats geometry)",
		},
		// backdoor_confirmed + unknown region: dark-delta beats geometry → base confidence unchanged
		{
			name:           "confirmed + unknown → base confidence + dark-delta-beats-geometry note",
			verdict:        "backdoor_confirmed",
			region:         regionUnknown,
			base:           base,
			wantConfidence: base,
			wantNote:       "geometry inconclusive but dark-region confirmed (dark-delta beats geometry)",
		},
		// indeterminate + console: unconfirmed but console-shaped → rerun note
		{
			name:           "indeterminate + console → base confidence + rerun note",
			verdict:        verdictIndeterminate,
			region:         regionConsoleLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "console-shaped, unconfirmed — rerun",
		},
		// indeterminate + dialog: unconfirmed dialog-shaped → rerun note
		{
			name:           "indeterminate + dialog → base confidence + rerun note",
			verdict:        verdictIndeterminate,
			region:         regionDialogLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "dialog-shaped, unconfirmed — rerun",
		},
		// indeterminate + unknown: geometry inconclusive → rerun note
		{
			name:           "indeterminate + unknown → base confidence + rerun note",
			verdict:        verdictIndeterminate,
			region:         regionUnknown,
			base:           base,
			wantConfidence: base,
			wantNote:       "geometry inconclusive, unconfirmed — rerun",
		},
		// clean verdict: no geometry enrichment, no note
		{
			name:           "clean → base confidence + empty note",
			verdict:        "clean",
			region:         regionConsoleLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "",
		},
		// other / arbitrary verdict: no spurious high confidence, no note
		{
			name:           "other verdict → base confidence + empty note",
			verdict:        "some_other_verdict",
			region:         regionConsoleLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotConf, gotNote := regionConfidenceAndNote(tc.verdict, tc.region, tc.base)
			assert.Equal(t, tc.wantConfidence, gotConf)
			assert.Equal(t, tc.wantNote, gotNote)
		})
	}
}
