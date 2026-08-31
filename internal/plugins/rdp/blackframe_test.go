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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the regression suite for the torn-down-session false positive.
//
// Observed in the field against a Windows host whose logon screen used the default
// Windows 10 "cave" wallpaper: the server dropped the pre-auth RDP session a few
// seconds in, sooner than the careful settle profile needs. pumpSession returned a
// session error, the caller discarded it, and captureFrame was then called on the
// dead session -- session_get_frame returns image.data() unconditionally
// (rust/src/session.rs), so a terminated ActiveStage hands back a perfectly black
// 1024x768 frame that looks like a successful capture.
//
// Differenced against a wallpaper that is already ~61% dark, that black frame:
//   - changes only ~39% of pixels, so it slips past maxChangedPercent's 80%
//     "full-screen change, not a window" guard,
//   - leaves the changed pixels (the bright part of the wallpaper) as one large
//     contiguous rectangle, so detectChangedRectangle scores it window-shaped,
//   - saturates the confidence formula at its 0.85 cap, and
//   - passes consoleGatePasses on every arm (mean brightness 0 <= 90, large area,
//     darkBoxFraction 1.0 >= 0.70).
//
// Result: "[HIGH] Sticky keys backdoor likely (confidence: 85%)" against a host
// where the trigger keystrokes were never even sent. The host was later confirmed
// clean -- with a short settle budget the same host renders the stock Windows
// "Do you want to turn on Sticky Keys?" dialog and the stock Ease of Access panel.

// darkWallpaperBaseline builds a baseline with the property that made the real
// wallpaper dangerous: most of it is ALREADY dark, so blanking the screen to black
// changes only a minority of pixels and never trips the full-screen-change guard.
// darkFrac of the rows are near-black; the rest are bright.
func darkWallpaperBaseline(w, h uint32, darkFrac float64) []byte {
	buf := make([]byte, int(w)*int(h)*4)
	darkRows := int(float64(h) * darkFrac)
	for y := 0; y < int(h); y++ {
		var r, g, b byte = 210, 200, 180 // bright sky/sand
		if y < darkRows {
			r, g, b = 6, 7, 9 // near-black cave
		}
		for x := 0; x < int(w); x++ {
			i := (y*int(w) + x) * 4
			buf[i], buf[i+1], buf[i+2], buf[i+3] = r, g, b, 255
		}
	}
	return buf
}

// TestTornDownSessionFrameIsNeverPositive is the cardinal regression: an all-black
// response against a mostly-dark real baseline must never yield a positive verdict.
// Before the fix this exact input produced backdoor_likely at 0.85 confidence.
func TestTornDownSessionFrameIsNeverPositive(t *testing.T) {
	w, h := uint32(1024), uint32(768)
	baseline := darkWallpaperBaseline(w, h, 0.61)
	black := make([]byte, int(w)*int(h)*4)
	for i := 3; i < len(black); i += 4 {
		black[i] = 255 // opaque, all-zero RGB -- exactly what a dead session returns
	}

	// Characterize the trap: the raw scorer still finds this "window-shaped", which
	// is why the guard has to sit in front of it rather than inside it.
	rawVerdict, rawConf, _ := analyzeBackdoorResponse(baseline, black, w, h)
	require.Equal(t, "backdoor_likely", rawVerdict,
		"fixture no longer reproduces the trap; the raw scorer must still be fooled for this test to be meaningful")
	require.InDelta(t, 0.85, rawConf, 0.001, "fixture should saturate the confidence cap, as the field case did")

	ctx := context.Background()

	sticky := runStickyKeysAnalysis(ctx, baseline, black, w, h, "")
	assert.Equal(t, verdictIndeterminate, sticky.OverallVerdict,
		"CARDINAL: a torn-down session's black frame must be indeterminate, never a finding")
	assert.NotEqual(t, "backdoor_likely", sticky.OverallVerdict)
	assert.NotEqual(t, "backdoor_confirmed", sticky.OverallVerdict)

	utilman := runUtilmanAnalysis(ctx, baseline, black, w, h, "")
	assert.Equal(t, verdictIndeterminate, utilman.OverallVerdict,
		"CARDINAL: same guard must hold on the utilman path")
	assert.NotEqual(t, "backdoor_likely", utilman.OverallVerdict)
	assert.NotEqual(t, "backdoor_confirmed", utilman.OverallVerdict)
}

// TestIsUniformFrame pins the predicate. A real console always carries text, a
// cursor or a border, so exact uniformity is the narrow signal for "no render",
// and the guard cannot suppress a genuine finding.
func TestIsUniformFrame(t *testing.T) {
	flatBlack := make([]byte, 64*4)
	for i := 3; i < len(flatBlack); i += 4 {
		flatBlack[i] = 255
	}
	flatGrey := make([]byte, 64*4)
	for i := 0; i < len(flatGrey); i += 4 {
		flatGrey[i], flatGrey[i+1], flatGrey[i+2], flatGrey[i+3] = 100, 100, 100, 255
	}
	// A console body: flat dark field plus a single lit cursor pixel.
	consoleish := make([]byte, 64*4)
	for i := 3; i < len(consoleish); i += 4 {
		consoleish[i] = 255
	}
	consoleish[40], consoleish[41], consoleish[42] = 200, 200, 200

	assert.True(t, isUniformFrame(flatBlack), "all-black surface is flat")
	assert.True(t, isUniformFrame(flatGrey), "any single color is flat, not just black")
	assert.False(t, isUniformFrame(consoleish),
		"one lit pixel is enough to be a render: the guard must not swallow a console")
	assert.True(t, isUniformFrame(nil), "no pixels carries no evidence")
}

// TestFlatBaselineAndResponseStaysClean guards the other direction: two flat frames
// are a genuine "nothing changed", not a torn-down session, and must stay clean.
// The guard is deliberately scoped to a flat response against a NON-flat baseline.
func TestFlatBaselineAndResponseStaysClean(t *testing.T) {
	w, h := uint32(50), uint32(50)
	size := int(w) * int(h) * 4
	flat := func() []byte {
		buf := make([]byte, size)
		for i := 0; i < size; i += 4 {
			buf[i], buf[i+1], buf[i+2], buf[i+3] = 100, 100, 100, 255
		}
		return buf
	}
	ctx := context.Background()
	assert.Equal(t, "clean", runStickyKeysAnalysis(ctx, flat(), flat(), w, h, "").OverallVerdict)
	assert.Equal(t, "clean", runUtilmanAnalysis(ctx, flat(), flat(), w, h, "").OverallVerdict)
}

// TestResponseFrameNeverReadsDeadSession covers the frame-selection seam. With a
// pump error the live framebuffer is untrustworthy, so the last frame seen while
// the session was alive wins, then the baseline. captureFrame is only reached on a
// clean pump, so inst may be nil here.
func TestResponseFrameNeverReadsDeadSession(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	baseline := []byte{1, 2, 3, 255}
	live := []byte{9, 9, 9, 255}
	pumpErr := errors.New("session error: session terminated: logoff by user")

	t.Run("prefers the last live frame", func(t *testing.T) {
		got, err := p.responseFrame(ctx, nil, 0, &sessionDiag{lastFrame: live}, baseline, pumpErr)
		require.NoError(t, err)
		assert.Equal(t, live, got,
			"a payload that painted before the drop must still be analyzed (no new false negatives)")
	})

	t.Run("falls back to the baseline", func(t *testing.T) {
		got, err := p.responseFrame(ctx, nil, 0, &sessionDiag{}, baseline, pumpErr)
		require.NoError(t, err)
		assert.Equal(t, baseline, got,
			"a session that died without painting analyzes as the original screen, i.e. no change")
	})

	t.Run("errors when nothing was ever observed", func(t *testing.T) {
		_, err := p.responseFrame(ctx, nil, 0, &sessionDiag{}, nil, pumpErr)
		require.Error(t, err, "no frame at all is a failed scan, not a clean one")
	})
}

// TestIndeterminateBanner checks the operator-facing text. "render did not
// stabilize -- rerun" sends the operator to repeat an identical scan that fails
// identically; a torn-down session needs the short profile instead.
func TestIndeterminateBanner(t *testing.T) {
	plain := indeterminateBanner("Sticky keys", false, "")
	assert.Contains(t, plain, "render did not stabilize")
	assert.NotContains(t, plain, "--fast")

	reason := "session terminated: [Protocol independent error] The disconnection was initiated by the user logging off his or her session on the server"
	withReason := indeterminateBanner("Sticky keys", true, reason)
	assert.Contains(t, withReason, "server ended the session mid-scan")
	assert.Contains(t, withReason, reason, "the server's own reason is the diagnostic; it must not be dropped")
	assert.Contains(t, withReason, "--fast", "the banner must name the actionable next step")

	noReason := indeterminateBanner("Utilman", true, "")
	assert.Contains(t, noReason, "server ended the session mid-scan")
	assert.Contains(t, noReason, "--fast")
}
