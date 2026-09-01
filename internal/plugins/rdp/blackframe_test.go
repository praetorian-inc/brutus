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

// TestRetryAfterTermination pins the retry gate. A terminated session whose scan
// still REPORTED something (responseFrame analyzes the last live frame, so a payload
// that painted and only then dropped the session scores a genuine positive) must not
// be re-run: the second scan can come back indeterminate and would replace a real
// backdoor with nothing -- the false negative the cardinal rule forbids.
func TestRetryAfterTermination(t *testing.T) {
	for _, tc := range []struct {
		verdict   string
		performed bool
		want      bool
		why       string
	}{
		{"backdoor_confirmed", true, false, "a confirmed backdoor is never re-rolled"},
		{"backdoor_likely", true, false, "a HIGH finding is never re-rolled"},
		{"vulnerable", true, false, "the non-NLA reading is a real observation too"},
		{verdictIndeterminate, true, true, "nothing was observed, so a retry can only improve it"},
		{"clean", true, true, "a clean from a torn-down session saw no post-trigger render"},
		{"", false, true, "a scan that never performed has nothing to lose"},
		{"backdoor_likely", false, true, "a verdict without Performed is not an observation"},
	} {
		assert.Equal(t, tc.want, retryAfterTermination(tc.verdict, tc.performed),
			"%s/performed=%v: %s", tc.verdict, tc.performed, tc.why)
	}
}

// TestTerminationBannerReachesTheOperator covers every banner seam that consumes
// SessionTerminated, including the !Performed path, where "could not connect"
// misdirects an operator whose connect worked and whose session was torn down after.
func TestTerminationBannerReachesTheOperator(t *testing.T) {
	const reason = "session terminated: logoff by user"

	t.Run("sticky indeterminate", func(t *testing.T) {
		got := mapStickyResult(&StickyKeysResult{
			Performed: true, OverallVerdict: verdictIndeterminate,
			SessionTerminated: true, TerminationReason: reason,
		}, "")
		assert.True(t, got.Indeterminate)
		assert.Contains(t, got.Banner, "server ended the session mid-scan")
		assert.Contains(t, got.Banner, reason)
	})

	t.Run("sticky not performed", func(t *testing.T) {
		got := mapStickyResult(&StickyKeysResult{
			Performed: false, SkipReason: "session failed: pump baseline: session error",
			SessionTerminated: true, TerminationReason: reason,
		}, "")
		assert.True(t, got.Indeterminate)
		assert.Contains(t, got.Banner, "server ended the session mid-scan")
		assert.NotContains(t, got.Banner, "could not connect",
			"a mid-scan teardown is not a failed connect")
	})

	t.Run("utilman indeterminate", func(t *testing.T) {
		got := mapUtilmanResult(&UtilmanResult{
			Performed: true, OverallVerdict: verdictIndeterminate,
			SessionTerminated: true, TerminationReason: reason,
		}, "")
		assert.Contains(t, got.Banner, "server ended the session mid-scan")
		assert.Contains(t, got.Banner, reason)
	})

	t.Run("a non-terminated indeterminate keeps the original text", func(t *testing.T) {
		got := mapStickyResult(&StickyKeysResult{
			Performed: true, OverallVerdict: verdictIndeterminate,
		}, "")
		assert.Contains(t, got.Banner, "render did not stabilize")
	})
}

// TestFinalizeResultKeepsTerminationDiagnostics is the regression test for the
// ordering trap that shipped broken: the analysis functions return a FRESH result, so
// a `*result = analysis` assignment discards anything set beforehand. When that
// happened, SessionTerminated silently went false, the short-profile retry never
// fired, and the banner fell back to "render did not stabilize" -- invisibly, because
// the scan itself still succeeded. This exercises the real production tail, not a
// mirror of it: reorder the assignments in finalize*Result and this fails.
func TestFinalizeResultKeepsTerminationDiagnostics(t *testing.T) {
	const reason = "session terminated: logoff by user"
	diag := sessionDiag{terminated: true, reason: reason}

	t.Run("sticky keys", func(t *testing.T) {
		result := &StickyKeysResult{Performed: true}
		// A torn-down session analyzes the baseline as the response -> "clean".
		finalizeStickyKeysResult(result, &StickyKeysResult{Performed: true, OverallVerdict: "clean"}, diag, false, false)

		assert.True(t, result.SessionTerminated,
			"the retry in DetectStickyKeys reads this field; zeroed, the retry never fires")
		assert.Equal(t, reason, result.TerminationReason,
			"the banner names the server's own reason; zeroed, the operator is told to rerun an identical scan")
		assert.Equal(t, verdictIndeterminate, result.OverallVerdict,
			"a clean on an unstable render is still downgraded (cardinal guard must survive the refactor)")
		assert.False(t, result.Stabilized)
		assert.True(t, result.Performed)
	})

	t.Run("utilman", func(t *testing.T) {
		result := &UtilmanResult{Performed: true}
		finalizeUtilmanResult(result, &UtilmanResult{Performed: true, OverallVerdict: "clean"}, diag, false, false)

		assert.True(t, result.SessionTerminated)
		assert.Equal(t, reason, result.TerminationReason)
		assert.Equal(t, verdictIndeterminate, result.OverallVerdict)
	})

	t.Run("a positive survives a terminated session", func(t *testing.T) {
		// The painted-then-dropped host: a real finding carried out alongside
		// terminated=true. It must reach the caller intact, because that pairing is
		// exactly what retryAfterTermination has to see to refuse the retry.
		result := &StickyKeysResult{Performed: true}
		finalizeStickyKeysResult(result, &StickyKeysResult{
			Performed: true, OverallVerdict: "backdoor_likely", Confidence: 0.85,
		}, diag, false, false)

		assert.Equal(t, "backdoor_likely", result.OverallVerdict,
			"a positive is never downgraded by the stabilized guard")
		assert.True(t, result.SessionTerminated)
		assert.False(t, retryAfterTermination(result.OverallVerdict, result.Performed),
			"the retry must refuse to overwrite this finding")
	})

	t.Run("analysis fields are not dropped", func(t *testing.T) {
		result := &StickyKeysResult{}
		finalizeStickyKeysResult(result, &StickyKeysResult{
			Performed: true, OverallVerdict: "backdoor_confirmed",
			Confidence: 0.95, HeuristicResult: "dark delta", RegionNote: "console-shaped",
		}, sessionDiag{}, true, false)

		assert.Equal(t, "backdoor_confirmed", result.OverallVerdict)
		assert.InDelta(t, 0.95, result.Confidence, 1e-9)
		assert.Equal(t, "dark delta", result.HeuristicResult)
		assert.Equal(t, "console-shaped", result.RegionNote)
		assert.False(t, result.SessionTerminated)
		assert.Empty(t, result.TerminationReason)
	})
}

// TestRetryOnTerminationWiring covers the retry DECISION as it is actually wired,
// not just the predicate behind it. The predicate was correct and the call site was
// what broke before, so this asserts the observable behavior: whether the rerun
// happens at all, and which result reaches the caller.
func TestRetryOnTerminationWiring(t *testing.T) {
	const reason = "session terminated: logoff by user"
	terminatedClean := func() *StickyKeysResult {
		return &StickyKeysResult{Performed: true, OverallVerdict: verdictIndeterminate,
			SessionTerminated: true, TerminationReason: reason}
	}

	t.Run("reruns an indeterminate teardown on the short profile", func(t *testing.T) {
		calls := 0
		second := &StickyKeysResult{Performed: true, OverallVerdict: "backdoor_likely"}
		got := retryStickyKeysOnTermination(false, terminatedClean(), func() *StickyKeysResult {
			calls++
			return second
		})
		assert.Equal(t, 1, calls, "a scan that observed no render must be retried")
		assert.Same(t, second, got)
	})

	t.Run("never overwrites a finding", func(t *testing.T) {
		for _, verdict := range []string{"backdoor_confirmed", "backdoor_likely", "vulnerable"} {
			first := &StickyKeysResult{Performed: true, OverallVerdict: verdict,
				SessionTerminated: true, TerminationReason: reason}
			calls := 0
			got := retryStickyKeysOnTermination(false, first, func() *StickyKeysResult {
				calls++
				return &StickyKeysResult{Performed: true, OverallVerdict: verdictIndeterminate}
			})
			assert.Zero(t, calls, "%s: retrying can only lose the finding (cardinal rule)", verdict)
			assert.Same(t, first, got)
		}
	})

	t.Run("does not fire without a teardown", func(t *testing.T) {
		first := &StickyKeysResult{Performed: true, OverallVerdict: verdictIndeterminate}
		calls := 0
		got := retryStickyKeysOnTermination(false, first, func() *StickyKeysResult {
			calls++
			return nil
		})
		assert.Zero(t, calls, "a plain unstable render has no shorter profile to gain from")
		assert.Same(t, first, got)
	})

	t.Run("does not fire in fast mode", func(t *testing.T) {
		calls := 0
		got := retryStickyKeysOnTermination(true, terminatedClean(), func() *StickyKeysResult {
			calls++
			return nil
		})
		assert.Zero(t, calls, "--fast is already the short profile; there is nothing to fall back to")
		assert.True(t, got.SessionTerminated)
	})

	t.Run("tolerates a nil result", func(t *testing.T) {
		calls := 0
		got := retryStickyKeysOnTermination(false, nil, func() *StickyKeysResult { calls++; return nil })
		assert.Zero(t, calls)
		assert.Nil(t, got)
	})

	t.Run("utilman is wired the same way", func(t *testing.T) {
		calls := 0
		first := &UtilmanResult{Performed: true, OverallVerdict: verdictIndeterminate, SessionTerminated: true}
		second := &UtilmanResult{Performed: true, OverallVerdict: "clean"}
		got := retryUtilmanOnTermination(false, first, func() *UtilmanResult { calls++; return second })
		assert.Equal(t, 1, calls)
		assert.Same(t, second, got)

		calls = 0
		positive := &UtilmanResult{Performed: true, OverallVerdict: "backdoor_likely", SessionTerminated: true}
		got = retryUtilmanOnTermination(false, positive, func() *UtilmanResult { calls++; return second })
		assert.Zero(t, calls)
		assert.Same(t, positive, got)
	})
}
