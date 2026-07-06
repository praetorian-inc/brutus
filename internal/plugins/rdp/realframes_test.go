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
	"fmt"
	"image"
	"image/draw"
	_ "image/png" // register PNG decoder for image.Decode
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFrameRGBA decodes a testdata PNG into the same RGBA byte layout the analyzer
// consumes: a tightly-packed buffer with stride = 4*width and pixel order R,G,B,A.
// The PNGs are lossless dumps of the live framebuffer, so decode round-trips the
// original pixels. We draw the decoded image into an image.RGBA to GUARANTEE the
// 4-byte stride and channel order regardless of the PNG's source color model
// (these dumps are 8-bit RGB, which decodes to *image.NRGBA / *image.RGBA — drawing
// into a fresh RGBA normalizes both to the layout pixelBrightness/darkPixelCount expect).
func loadFrameRGBA(t *testing.T, name string) (pix []byte, width, height uint32) {
	t.Helper()
	path := filepath.Join("testdata", "realframes", name)
	f, err := os.Open(path)
	require.NoError(t, err, "open fixture %s", path)
	defer func() { _ = f.Close() }()

	img, format, err := image.Decode(f)
	require.NoError(t, err, "decode fixture %s", path)
	require.Equal(t, "png", format, "fixture %s must be PNG", path)

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(rgba, rgba.Bounds(), img, b.Min, draw.Src)

	// Confirm stride == 4*width (the analyzer's hard assumption).
	require.Equal(t, 4*w, rgba.Stride, "fixture %s: stride must be 4*width", name)
	return rgba.Pix, uint32(w), uint32(h)
}

// realFrameFixture pairs a baseline+response fixture with its expected gate outcome.
type realFrameFixture struct {
	name         string // logical fixture name
	baselineFile string
	responseFile string
	wantHigh     bool   // true => must be backdoor_likely (HIGH); false => must NOT be HIGH
	analysis     string // "sticky" or "utilman" — which public path captured this frame
}

var realFrameFixtures = []realFrameFixture{
	{
		name:         "fp_clean_utilman",
		baselineFile: "fp_clean_utilman_baseline.png",
		responseFile: "fp_clean_utilman_response.png",
		wantHigh:     false, // CLEAN host wallpaper FP — must be downgraded (NOT backdoor_likely)
		analysis:     "utilman",
	},
	{
		name:         "tp_cmd_sticky",
		baselineFile: "tp_cmd_sticky_baseline.png",
		responseFile: "tp_cmd_sticky_response.png",
		wantHigh:     true, // REAL cmd.exe console via sticky — must be HIGH
		analysis:     "sticky",
	},
	{
		name:         "tp_cmd2_sticky",
		baselineFile: "tp_cmd2_sticky_baseline.png",
		responseFile: "tp_cmd2_sticky_response.png",
		wantHigh:     true, // another REAL cmd console — must be HIGH
		analysis:     "sticky",
	},
	{
		name:         "tp_ps_utilman",
		baselineFile: "tp_ps_utilman_baseline.png",
		responseFile: "tp_ps_utilman_response.png",
		wantHigh:     true, // REAL windowed PowerShell console — must be HIGH (recall-risk case)
		analysis:     "utilman",
	},
}

// runFixture drives a fixture through its real public analysis path and returns the result verdict.
func runFixtureVerdict(fx realFrameFixture, baseline, response []byte, w, h uint32) string {
	ctx := context.Background()
	if fx.analysis == "sticky" {
		return runStickyKeysAnalysis(ctx, baseline, response, w, h, "").OverallVerdict
	}
	return runUtilmanAnalysis(ctx, baseline, response, w, h, "").OverallVerdict
}

// TestRealFrames_SanityDecode confirms the PNG→RGBA decode round-trips the framebuffer:
// the cmd-console response must contain a large count of dark pixels (a real black console
// body), proving byte order / stride match what darkPixelCount expects.
func TestRealFrames_SanityDecode(t *testing.T) {
	pix, w, h := loadFrameRGBA(t, "tp_cmd_sticky_response.png")
	total := int(w) * int(h)
	dark := darkPixelCount(pix, w, h)
	frac := float64(dark) / float64(total)
	t.Logf("tp_cmd_sticky_response: %dx%d, darkPixelCount=%d (%.1f%% of frame)", w, h, dark, frac*100)
	assert.Greater(t, frac, 0.04,
		"cmd console response must be substantially dark (>4%%) — confirms decode round-trips the framebuffer")
}

// TestRealFrames_GateRegression is the PERMANENT regression test against ground-truth
// captures. It drives each fixture through its real public analysis path (no WASM, no
// network) and asserts the gate's final verdict matches reality:
//   - all tp_* real consoles  → backdoor_likely (HIGH)
//   - the fp_clean wallpaper FP → indeterminate (downgraded, NOT backdoor_likely, NOT clean)
//
// CARDINAL: a real positive is never downgraded to clean; the FP is never kept HIGH.
func TestRealFrames_GateRegression(t *testing.T) {
	for _, fx := range realFrameFixtures {
		t.Run(fx.name, func(t *testing.T) {
			baseline, w, h := loadFrameRGBA(t, fx.baselineFile)
			response, w2, h2 := loadFrameRGBA(t, fx.responseFile)
			require.Equal(t, w, w2)
			require.Equal(t, h, h2)

			verdict := runFixtureVerdict(fx, baseline, response, w, h)

			if fx.wantHigh {
				assert.Equal(t, "backdoor_likely", verdict,
					"%s: REAL console must stay HIGH (backdoor_likely), got %q", fx.name, verdict)
			} else {
				assert.Equal(t, verdictIndeterminate, verdict,
					"%s: wallpaper FP must be downgraded to indeterminate, got %q", fx.name, verdict)
				assert.NotEqual(t, "backdoor_likely", verdict,
					"%s: CARDINAL — FP must NOT be kept backdoor_likely", fx.name)
				assert.NotEqual(t, "clean", verdict,
					"%s: CARDINAL — FP must NOT collapse to clean", fx.name)
			}
		})
	}
}

// TestRealFrames_Diagnostic is INSTRUMENTATION (not an assertion gate). It prints the real
// measured gate-input values for every fixture pair so the gate can be tuned against ground
// truth. Run with: go test -run TestRealFrames_Diagnostic -v ./internal/plugins/rdp/
func TestRealFrames_Diagnostic(t *testing.T) {
	fmt.Printf("\n%-16s %-8s %-16s %-6s %-9s %-9s %-9s %-9s %-9s %-6s %-16s\n",
		"fixture", "want", "rawVerdict", "conf", "fillRatio", "areaFrac", "meanBox", "darkInBox", "isRect", "keep", "finalVerdict")
	for _, fx := range realFrameFixtures {
		baseline, w, h := loadFrameRGBA(t, fx.baselineFile)
		response, w2, h2 := loadFrameRGBA(t, fx.responseFile)
		require.Equal(t, w, w2)
		require.Equal(t, h, h2)

		rawVerdict := darkDeltaVerdict(baseline, response, w, h)
		_, confidence, _ := analyzeBackdoorResponse(baseline, response, w, h)
		isRect, _, box := detectChangedRectangle(baseline, response, w, h)

		areaFrac := 0.0
		meanBox := 0
		darkInBox := 0.0
		if box.maxX > box.minX && box.maxY > box.minY {
			wInt := int(w)
			boxArea := (box.maxX - box.minX + 1) * (box.maxY - box.minY + 1)
			areaFrac = float64(boxArea) / float64(int(w)*int(h))
			meanBox = meanBoxBrightness(response, wInt, box)
			// dark fraction inside the box
			darkCount := 0
			for y := box.minY; y <= box.maxY; y++ {
				for x := box.minX; x <= box.maxX; x++ {
					idx := (y*wInt + x) * 4
					if idx+2 >= len(response) {
						continue
					}
					if pixelBrightness(response, idx) < darkBrightnessMax {
						darkCount++
					}
				}
			}
			darkInBox = float64(darkCount) / float64(boxArea)
		}

		keepHigh := consoleGatePasses(response, w, h, box, confidence)
		finalVerdict := decideVerdict(rawVerdict, keepHigh)

		wantStr := "HIGH"
		if !fx.wantHigh {
			wantStr = "not-HIGH"
		}
		fmt.Printf("%-16s %-8s %-16s %-6.3f %-9.3f %-9.4f %-9d %-9.3f %-9v %-6v %-16s\n",
			fx.name, wantStr, rawVerdict, confidence, box.fillRatio, areaFrac, meanBox, darkInBox, isRect, keepHigh, finalVerdict)
	}
	fmt.Println()
}
