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
	result := runUtilmanAnalysis(ctx, baseline, response, w, h, "", nonceSkipped)
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
// A3: decideVerdict — full 7-row table + cardinal rule
// ---------------------------------------------------------------------------

func TestDecideVerdict(t *testing.T) {
	tests := []struct {
		name      string
		heuristic string
		region    regionSignal
		nonce     nonceResult
		want      string
	}{
		{"clean heuristic stays clean", "clean", regionUnknown, nonceSkipped, "clean"},
		{"confirmed echo + console", "backdoor_likely", regionConsoleLike, nonceConfirmed, "backdoor_confirmed"},
		{"confirmed echo beats dialog geometry", "backdoor_likely", regionDialogLike, nonceConfirmed, "backdoor_confirmed"},
		{"console but no echo -> rerun", "backdoor_likely", regionConsoleLike, nonceUnconfirmed, verdictIndeterminate},
		{"dialog + no echo -> rerun (the FP fix)", "backdoor_likely", regionDialogLike, nonceUnconfirmed, verdictIndeterminate},
		{"unknown + no echo -> rerun", "backdoor_likely", regionUnknown, nonceUnconfirmed, verdictIndeterminate},
		{"backdoor box but nonce skipped -> rerun", "backdoor_likely", regionConsoleLike, nonceSkipped, verdictIndeterminate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decideVerdict(tc.heuristic, tc.region, tc.nonce)
			assert.Equal(t, tc.want, got)
			if tc.heuristic == "backdoor_likely" {
				assert.NotEqual(t, "clean", got, "CARDINAL RULE: backdoor box must never become clean")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A4: runStickyKeysAnalysis — dialog-shaped frame → indeterminate (not backdoor_likely)
// ---------------------------------------------------------------------------

func TestRunStickyKeysAnalysis_DialogShape_NoVision_Indeterminate(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	size := int(w) * int(h) * 4
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i], baseline[i+1], baseline[i+2], baseline[i+3] = 128, 128, 128, 255
	}
	response := make([]byte, size)
	copy(response, baseline)
	paintBox(response, int(w), 390, 390, 610, 610, 200) // light small centered (220×220 = 4.84% area, trips heuristic but classifies as dialog)
	res := runStickyKeysAnalysis(context.Background(), baseline, response, w, h, "", nonceSkipped)
	assert.Equal(t, verdictIndeterminate, res.OverallVerdict)
	assert.NotEqual(t, "clean", res.OverallVerdict)
}

// ---------------------------------------------------------------------------
// B1: verifyEcho — pure pixel-diff confirms or denies a shell echo
// ---------------------------------------------------------------------------

func TestVerifyEcho_Confirmed(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	size := int(w) * int(h) * 4
	before := make([]byte, size)
	paintBox(before, int(w), 0, 0, 600, 600, 0) // dark console
	after := make([]byte, size)
	copy(after, before)
	// new text rendered inside box (rows of light pixels = echoed line + prompt)
	paintBox(after, int(w), 10, 500, 590, 560, 230)
	box := changedBox{minX: 0, minY: 0, maxX: 599, maxY: 599}
	assert.Equal(t, nonceConfirmed, verifyEcho(before, after, w, h, box))
}

func TestVerifyEcho_Unconfirmed(t *testing.T) {
	w, h := uint32(1000), uint32(1000)
	size := int(w) * int(h) * 4
	before := make([]byte, size)
	paintBox(before, int(w), 430, 430, 570, 570, 200) // static dialog
	after := make([]byte, size)
	copy(after, before) // nothing changed
	box := changedBox{minX: 430, minY: 430, maxX: 569, maxY: 569}
	assert.Equal(t, nonceUnconfirmed, verifyEcho(before, after, w, h, box))
}

// ---------------------------------------------------------------------------
// C1: structural guard — runStickyKeysAnalysis must have the vulnerable branch
// ---------------------------------------------------------------------------

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
			wantNote:       "console-shaped + behaviorally confirmed",
		},
		// backdoor_confirmed + dialog-shaped: echo beats geometry → base confidence unchanged
		{
			name:           "confirmed + dialog → base confidence + echo-beats-geometry note",
			verdict:        "backdoor_confirmed",
			region:         regionDialogLike,
			base:           base,
			wantConfidence: base,
			wantNote:       "dialog-shaped but behaviorally confirmed (echo beats geometry)",
		},
		// backdoor_confirmed + unknown region: echo beats geometry → base confidence unchanged
		{
			name:           "confirmed + unknown → base confidence + echo-beats-geometry note",
			verdict:        "backdoor_confirmed",
			region:         regionUnknown,
			base:           base,
			wantConfidence: base,
			wantNote:       "geometry inconclusive but behaviorally confirmed (echo beats geometry)",
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
