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
	"github.com/praetorian-inc/brutus/pkg/brutus"
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
		assert.False(t, r.Success)
		assert.False(t, r.Indeterminate, "nla_required is TERMINAL, not indeterminate")
		assert.Contains(t, r.Banner, "nla_required")
		assert.Equal(t, "rdp", r.Protocol)
		assert.Equal(t, "10.0.0.5:3389", r.Target)
	}
	assert.Equal(t, "sticky_keys", rs[0].ScanType)
	assert.Equal(t, "utilman", rs[1].ScanType)
}

// TestNLARequiredResults_StickyOnly verifies that CheckStickyKeys produces a
// single sticky_keys result.
func TestNLARequiredResults_StickyOnly(t *testing.T) {
	rs := NLARequiredResults("h:3389", CheckStickyKeys)
	require.Len(t, rs, 1)
	assert.Equal(t, "sticky_keys", rs[0].ScanType)
	assert.False(t, rs[0].Success)
	assert.False(t, rs[0].Indeterminate)
	assert.Contains(t, rs[0].Banner, "nla_required")
}

// TestNLARequiredResults_UtilmanOnly verifies that CheckUtilman produces a
// single utilman result.
func TestNLARequiredResults_UtilmanOnly(t *testing.T) {
	rs := NLARequiredResults("h:3389", CheckUtilman)
	require.Len(t, rs, 1)
	assert.Equal(t, "utilman", rs[0].ScanType)
	assert.False(t, rs[0].Success)
	assert.False(t, rs[0].Indeterminate)
	assert.Contains(t, rs[0].Banner, "nla_required")
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
	runDetection = func(ctx context.Context, target string, timeout time.Duration, aiMode bool, checks Check) ([]brutus.Result, bool) {
		ranDetection.Store(true) // must NOT be called for nla_required
		return nil, false
	}
	nlaProbe = func(ctx context.Context, target string, timeout time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoNLARequired
	}

	rs, ok := DetectBackdoors(context.Background(), "h:3389", time.Second, false, 2, CheckBoth, "", false)
	assert.False(t, ok)
	assert.False(t, ranDetection.Load(),
		"WASM detection must be skipped for nla_required (no decode slot must be acquired)")
	require.Len(t, rs, 2)
	assert.Contains(t, rs[0].Banner, "nla_required")
	assert.False(t, rs[0].Indeterminate,
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
	runDetection = func(ctx context.Context, target string, timeout time.Duration, aiMode bool, checks Check) ([]brutus.Result, bool) {
		ran.Store(true)
		return []brutus.Result{
			{ScanType: "sticky_keys"},
			{ScanType: "utilman"},
		}, false
	}
	nlaProbe = func(ctx context.Context, target string, timeout time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoProbeError
	}

	_, _ = DetectBackdoors(context.Background(), "h:3389", time.Second, false, 0, CheckBoth, "", false)
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
	nlaProbe = func(ctx context.Context, target string, timeout time.Duration, proxyURL string) rdp.NegoClass {
		probed.Store(true)
		return rdp.NegoNLARequired
	}
	runDetection = func(ctx context.Context, target string, timeout time.Duration, aiMode bool, checks Check) ([]brutus.Result, bool) {
		return []brutus.Result{{ScanType: "sticky_keys"}}, false
	}

	_, _ = DetectBackdoors(context.Background(), "h:3389", time.Second, false, 0, CheckStickyKeys, "", true /*noNLAProbe*/)
	assert.False(t, probed.Load(),
		"--no-nla-probe must bypass the probe entirely (noNLAProbe=true)")
}
