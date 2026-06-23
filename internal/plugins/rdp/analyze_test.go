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
func paintBox(buf []byte, w int, x0, y0, x1, y1 int, gray byte) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			idx := (y*w + x) * 4
			buf[idx], buf[idx+1], buf[idx+2], buf[idx+3] = gray, gray, gray, 255
		}
	}
}

// paintBoxRGB fills a rectangular region with explicit RGB values.
// Used for themed-console tests (e.g. PowerShell blue, brightness ~31).
func paintBoxRGB(buf []byte, w int, x0, y0, x1, y1 int, r, g, b byte) {
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
// A3: decideVerdict — pass-through + cardinal rule
// decideVerdict(verdict, region) is now a pure pass-through: whatever verdict
// comes in (from darkDeltaVerdict) goes out unchanged. The cardinal rule is
// that a "backdoor_likely" verdict must never become "clean".
// ---------------------------------------------------------------------------

func TestDecideVerdict(t *testing.T) {
	tests := []struct {
		name      string
		heuristic string
		region    regionSignal
		want      string
	}{
		// Pass-through: clean stays clean regardless of region.
		{"clean stays clean (unknown region)", "clean", regionUnknown, "clean"},
		{"clean stays clean (console region)", "clean", regionConsoleLike, "clean"},
		{"clean stays clean (dialog region)", "clean", regionDialogLike, "clean"},
		// Pass-through: backdoor_likely stays backdoor_likely.
		{"backdoor_likely stays (unknown region)", "backdoor_likely", regionUnknown, "backdoor_likely"},
		{"backdoor_likely stays (console region)", "backdoor_likely", regionConsoleLike, "backdoor_likely"},
		{"backdoor_likely stays (dialog region)", "backdoor_likely", regionDialogLike, "backdoor_likely"},
		// Pass-through: indeterminate stays indeterminate.
		{"indeterminate stays (unknown region)", verdictIndeterminate, regionUnknown, verdictIndeterminate},
		{"indeterminate stays (console region)", verdictIndeterminate, regionConsoleLike, verdictIndeterminate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decideVerdict(tc.heuristic, tc.region)
			assert.Equal(t, tc.want, got)
			// CARDINAL RULE: a backdoor_likely in must never yield clean out.
			if tc.heuristic == "backdoor_likely" {
				assert.NotEqual(t, "clean", got, "CARDINAL RULE: backdoor_likely must never become clean")
			}
		})
	}
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
