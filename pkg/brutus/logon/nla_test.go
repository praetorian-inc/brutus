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

package logon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
)

// ---------------------------------------------------------------------------
// Task 1.4 — NLARequiredResults constructor tests
// ---------------------------------------------------------------------------

// TestNLARequiredResults_Both verifies that CheckBoth produces 2 results, one
// for sticky_keys and one for utilman, both with Success=false,
// Indeterminate=false, and a banner containing "nla_required".
//
// This test is RED until the developer implements NLARequiredResults().
func TestNLARequiredResults_Both(t *testing.T) {
	rs := NLARequiredResults("10.0.0.5:3389", CheckBoth)
	require.Len(t, rs, 2)
	for _, r := range rs {
		assert.False(t, r.Verdict.Positive())
		assert.False(t, r.Verdict.NeedsRerun(), "nla_required is TERMINAL, not a rerun candidate")
		assert.Equal(t, VerdictNLARequired, r.Verdict)
		assert.Equal(t, "10.0.0.5:3389", r.Target)
	}
	assert.Equal(t, BackdoorStickyKeys, rs[0].Check)
	assert.Equal(t, BackdoorUtilman, rs[1].Check)
}

// TestNLARequiredResults_StickyOnly verifies that CheckStickyKeys produces a
// single sticky_keys result.
func TestNLARequiredResults_StickyOnly(t *testing.T) {
	rs := NLARequiredResults("h:3389", CheckStickyKeys)
	require.Len(t, rs, 1)
	assert.Equal(t, BackdoorStickyKeys, rs[0].Check)
	assert.False(t, rs[0].Verdict.Positive())
	assert.False(t, rs[0].Verdict.NeedsRerun())
	assert.Equal(t, VerdictNLARequired, rs[0].Verdict)
}

// TestNLARequiredResults_UtilmanOnly verifies that CheckUtilman produces a
// single utilman result.
func TestNLARequiredResults_UtilmanOnly(t *testing.T) {
	rs := NLARequiredResults("h:3389", CheckUtilman)
	require.Len(t, rs, 1)
	assert.Equal(t, BackdoorUtilman, rs[0].Check)
	assert.False(t, rs[0].Verdict.Positive())
	assert.False(t, rs[0].Verdict.NeedsRerun())
	assert.Equal(t, VerdictNLARequired, rs[0].Verdict)
}

// ---------------------------------------------------------------------------
// Task 1.5 — DetectBackdoors seam tests (nlaProbe + runDetection)
// ---------------------------------------------------------------------------

// TestDetectBackdoors_NLARequired_SkipsWASM verifies that when the nlaProbe
// seam returns NegoNLARequired, DetectBackdoors returns a terminal nla_required
// verdict WITHOUT ever invoking runDetection (i.e., without acquiring a decode
// slot or touching WASM).
//
// This test is RED until the developer adds the nlaProbe seam and the
// pre-WASM short-circuit to DetectBackdoors (Task 1.5), which also requires
// the new DetectBackdoors signature:
//
//	DetectBackdoors(ctx, target, timeout, aiMode, maxRetries, checks, proxyURL, noNLAProbe)
func TestDetectBackdoors_NLARequired_SkipsWASM(t *testing.T) {
	withDecodeSlots(t, 4)

	origProbe := nlaProbe
	origRun := runDetection
	t.Cleanup(func() {
		nlaProbe = origProbe
		runDetection = origRun
	})

	var ranDetection atomic.Bool
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		ranDetection.Store(true) // must NOT be called for nla_required
		return nil
	}
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoNLARequired
	}

	rs := DetectBackdoors(context.Background(), "h:3389", 3*time.Second, time.Second, false, 2, CheckBoth, "", false, false)
	assert.False(t, AnyPositive(rs))
	assert.False(t, ranDetection.Load(),
		"WASM detection must be skipped for nla_required (no decode slot must be acquired)")
	require.Len(t, rs, 2)
	assert.Equal(t, VerdictNLARequired, rs[0].Verdict)
	assert.False(t, rs[0].Verdict.NeedsRerun(),
		"nla_required is a terminal non-retryable verdict, not indeterminate")
}

// TestDetectBackdoors_ProbeError_ProceedsToWASM verifies that when the nlaProbe
// seam returns NegoProbeError (dial/probe failure), DetectBackdoors falls
// through to the WASM path — a failed probe must never skip detection.
func TestDetectBackdoors_ProbeError_ProceedsToWASM(t *testing.T) {
	withDecodeSlots(t, 4)

	origProbe := nlaProbe
	origRun := runDetection
	t.Cleanup(func() {
		nlaProbe = origProbe
		runDetection = origRun
	})

	var ran atomic.Bool
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		ran.Store(true)
		return []Finding{
			{Check: BackdoorStickyKeys, Verdict: VerdictClean},
			{Check: BackdoorUtilman, Verdict: VerdictClean},
		}
	}
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoProbeError
	}

	_ = DetectBackdoors(context.Background(), "h:3389", 3*time.Second, time.Second, false, 0, CheckBoth, "", false, false)
	assert.True(t, ran.Load(),
		"probe error must fall through to WASM detection (fail-open)")
}

// TestDetectBackdoors_NoNLAProbe_SkipsProbe verifies that when noNLAProbe=true,
// the nlaProbe seam is never called even if it would return NLARequired.
func TestDetectBackdoors_NoNLAProbe_SkipsProbe(t *testing.T) {
	withDecodeSlots(t, 4)

	origProbe := nlaProbe
	origRun := runDetection
	t.Cleanup(func() {
		nlaProbe = origProbe
		runDetection = origRun
	})

	var probed atomic.Bool
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		probed.Store(true)
		return rdp.NegoNLARequired
	}
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		return []Finding{{Check: BackdoorStickyKeys, Verdict: VerdictClean}}
	}

	_ = DetectBackdoors(context.Background(), "h:3389", 3*time.Second, time.Second, false, 0, CheckStickyKeys, "", true /*noNLAProbe*/, false)
	assert.False(t, probed.Load(),
		"--no-nla-probe must bypass the probe entirely (noNLAProbe=true)")
}

// ---------------------------------------------------------------------------
// Task 2 — nlaProbe dial-failure → NegoUnreachable
// ---------------------------------------------------------------------------

// TestNLAProbe_DialFailure_ReturnsUnreachable verifies that when the TCP dial
// fails, nlaProbe classifies the host as NegoUnreachable (not NegoProbeError).
// 192.0.2.0/24 is TEST-NET-1 (RFC 5737); :1 refuses/black-holes fast.
func TestNLAProbe_DialFailure_ReturnsUnreachable(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737); :1 refuses/black-holes fast.
	got := nlaProbe(context.Background(), "192.0.2.1:1", 200*time.Millisecond /*connectTimeout*/, 100*time.Millisecond /*readDeadline*/, "")
	assert.Equal(t, rdp.NegoUnreachable, got,
		"a failed TCP dial must classify as NegoUnreachable, not NegoProbeError")
}

// ---------------------------------------------------------------------------
// Task 3 — UnreachableResults constructor tests
// ---------------------------------------------------------------------------

// TestUnreachableResults_Both verifies that CheckBoth produces 2 results, one
// for sticky_keys and one for utilman, both terminal (Success=false,
// Indeterminate=false) with a banner containing the "unreachable" token.
func TestUnreachableResults_Both(t *testing.T) {
	rs := UnreachableResults("10.0.0.5:3389", CheckBoth)
	require.Len(t, rs, 2)
	for _, r := range rs {
		assert.False(t, r.Verdict.Positive())
		assert.False(t, r.Verdict.NeedsRerun(), "unreachable is TERMINAL, not a rerun candidate")
		assert.Equal(t, VerdictUnreachable, r.Verdict)
		assert.Equal(t, "10.0.0.5:3389", r.Target)
	}
	assert.Equal(t, BackdoorStickyKeys, rs[0].Check)
	assert.Equal(t, BackdoorUtilman, rs[1].Check)
}

// TestUnreachableResults_StickyOnly verifies that CheckStickyKeys produces a
// single sticky_keys result with the correct terminal state.
func TestUnreachableResults_StickyOnly(t *testing.T) {
	rs := UnreachableResults("h:3389", CheckStickyKeys)
	require.Len(t, rs, 1)
	assert.Equal(t, BackdoorStickyKeys, rs[0].Check)
	assert.False(t, rs[0].Verdict.Positive())
	assert.False(t, rs[0].Verdict.NeedsRerun())
	assert.Equal(t, VerdictUnreachable, rs[0].Verdict)
}

// TestUnreachableResults_UtilmanOnly verifies that CheckUtilman produces a
// single utilman result with the correct terminal state.
func TestUnreachableResults_UtilmanOnly(t *testing.T) {
	rs := UnreachableResults("h:3389", CheckUtilman)
	require.Len(t, rs, 1)
	assert.Equal(t, BackdoorUtilman, rs[0].Check)
	assert.False(t, rs[0].Verdict.Positive())
	assert.False(t, rs[0].Verdict.NeedsRerun())
	assert.Equal(t, VerdictUnreachable, rs[0].Verdict)
}

// ---------------------------------------------------------------------------
// Task 4 — DetectBackdoors: NegoUnreachable short-circuits before decode slot
// ---------------------------------------------------------------------------

// TestDetectBackdoors_Unreachable_SkipsWASM verifies that when nlaProbe returns
// NegoUnreachable, DetectBackdoors returns a terminal unreachable verdict
// WITHOUT invoking runDetection (no decode slot acquired) and the results are
// NON-retryable (Indeterminate=false).
func TestDetectBackdoors_Unreachable_SkipsWASM(t *testing.T) {
	withDecodeSlots(t, 4)
	origProbe := nlaProbe
	origRun := runDetection
	t.Cleanup(func() { nlaProbe = origProbe; runDetection = origRun })

	var ranDetection atomic.Bool
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		ranDetection.Store(true)
		return nil
	}
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoUnreachable
	}

	rs := DetectBackdoors(context.Background(), "h:3389", 3*time.Second /*connectTimeout*/, time.Second /*timeout*/, false, 2, CheckBoth, "", false, false)
	assert.False(t, AnyPositive(rs))
	assert.False(t, ranDetection.Load(), "WASM detection must be skipped for unreachable (no decode slot)")
	require.Len(t, rs, 2)
	assert.Equal(t, VerdictUnreachable, rs[0].Verdict)
	assert.False(t, rs[0].Verdict.NeedsRerun(), "unreachable is terminal, non-retryable")
}
