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

// TestSequential verifies that runDetection (the fallback sequential form
// introduced in Phase D) runs sticky keys THEN utilman in order, under the
// single held decode slot, with no early-exit: even when the sticky fake
// returns a positive backdoor result the utilman fake is still invoked.
//
// It drives the detectSticky / detectUtilman seam vars, so a parallel
// implementation fails inside the utilman fake rather than silently.
func TestSequential(t *testing.T) {
	// Use a small semaphore so the decode slot is available.
	withDecodeSlots(t, 1)

	// stickyDone is set to true by the sticky fake immediately before it returns.
	// The utilman fake reads this flag: if the sequential impl is correct, sticky
	// must have finished before utilman starts, so the flag must already be true
	// when utilman begins. A parallel impl would race and this assertion would
	// fail intermittently (or consistently under the race detector).
	var stickyDone atomic.Bool

	// invocationOrder records which fake was called, in the order calls happen.
	var invocationOrder []string

	// origSticky / origUtilman are saved so Cleanup can restore them.
	origSticky := detectSticky
	origUtilman := detectUtilman
	origProbe := nlaProbe
	t.Cleanup(func() {
		detectSticky = origSticky
		detectUtilman = origUtilman
		nlaProbe = origProbe
	})

	// Stub the NLA probe to return NegoScannable so the test exercises the WASM path.
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}

	// Sticky fake: returns a positive verdict so we can assert that a positive
	// sticky does NOT suppress the utilman check.
	detectSticky = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome {
		invocationOrder = append(invocationOrder, "sticky")
		// Signal that sticky has finished its work.
		stickyDone.Store(true)
		return &rdp.CheckOutcome{
			Check: rdp.BackdoorStickyKeys, Performed: true, Stabilized: true,
			Verdict: "backdoor_confirmed", Confidence: 1.0,
		}
	}

	// Utilman fake: asserts that sticky completed before utilman started.
	detectUtilman = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome {
		// If sticky did not finish before utilman began, the sequential ordering
		// guarantee is violated. This assertion fires inside the fake so that a
		// parallel implementation causes the test to fail during DetectBackdoors.
		assert.True(t, stickyDone.Load(),
			"utilman fake called before stickyDone was set: execution was not sequential")
		invocationOrder = append(invocationOrder, "utilman")
		return &rdp.CheckOutcome{
			Check: rdp.BackdoorUtilman, Performed: true, Stabilized: true,
			Verdict: "clean",
		}
	}

	const target = "127.0.0.1:3389"
	// Signature: (ctx, target, connectTimeout, timeout, aiMode, maxRetries, checks, proxyURL, noNLAProbe, fast)
	// proxyURL="", noNLAProbe=false (nlaProbe seam already stubbed to NegoScannable above), fast=false.
	findings := DetectBackdoors(context.Background(), target, 3*time.Second /*connectTimeout*/, 5*time.Second /*timeout*/, false, 0 /*maxRetries*/, CheckBoth, "", false, false)

	// --- Assertion 1: both checks ran (no early-exit) ---
	require.Len(t, findings, 2,
		"expected exactly 2 findings (sticky + utilman), got %d", len(findings))

	// --- Assertion 2: both fakes were invoked ---
	assert.Contains(t, invocationOrder, "sticky", "sticky fake was never called")
	assert.Contains(t, invocationOrder, "utilman",
		"utilman fake was never called — early-exit on positive sticky is forbidden")

	// --- Assertion 3: sticky-first ordering in the result slice ---
	require.Equal(t, 2, len(invocationOrder),
		"expected exactly 2 fake invocations, got %d", len(invocationOrder))
	assert.Equal(t, "sticky", invocationOrder[0],
		"first result must be sticky keys, got %q", invocationOrder[0])
	assert.Equal(t, "utilman", invocationOrder[1],
		"second result must be utilman, got %q", invocationOrder[1])

	// --- Assertion 4: finding slice order is sticky-first ---
	assert.Equal(t, BackdoorStickyKeys, findings[0].Check, "findings[0] must be sticky keys")
	assert.Equal(t, BackdoorUtilman, findings[1].Check, "findings[1] must be utilman")

	// --- Assertion 5: utilman ran even though sticky was a positive ---
	assert.True(t, findings[0].Verdict.Positive(), "sticky finding should be a positive (positive fake)")
	// The utilman fake reads clean; a positive sticky then downgrades it to
	// indeterminate (contamination), which is exactly what must NOT happen to a
	// suppressed check -- it proves utilman actually ran.
	assert.Equal(t, VerdictIndeterminate, findings[1].Verdict,
		"a clean utilman after a positive sticky is downgraded, not suppressed")
}

// TestDetectBackdoors_FastPropagates verifies the fast flag reaches detectSticky/
// detectUtilman unchanged on every attempt (no promotion-to-careful on retry).
//
// Design decision D3 from the plan: fast mode uses FastBudget + fast=true on
// every attempt; --retries still works but retries stay fast.
//
// RED until the developer adds the trailing `fast bool` parameter to
// DetectBackdoors (logon.go:49), passes it to runDetection (logon.go:85),
// and runDetection passes it to detectSticky/detectUtilman (admission.go:94,98).
func TestDetectBackdoors_FastPropagates(t *testing.T) {
	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var seenFast []bool
	origSticky := detectSticky
	detectSticky = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome {
		seenFast = append(seenFast, fast)
		return &rdp.CheckOutcome{Check: rdp.BackdoorStickyKeys, Performed: true, Verdict: "indeterminate"}
	}
	origUtilman := detectUtilman
	detectUtilman = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome {
		seenFast = append(seenFast, fast)
		return &rdp.CheckOutcome{Check: rdp.BackdoorUtilman, Performed: true, Verdict: "indeterminate"}
	}
	t.Cleanup(func() { nlaProbe = origProbe; detectSticky = origSticky; detectUtilman = origUtilman })

	// fast=true, maxRetries=1 => 2 attempts (initial + 1 retry); both must carry fast=true.
	_ = DetectBackdoors(context.Background(), "host:3389", 3*time.Second, 5*time.Second, false, 1, CheckBoth, "", false, true)
	require.GreaterOrEqual(t, len(seenFast), 2, "fast pass with 1 retry runs >=2 detect calls")
	for i, f := range seenFast {
		assert.True(t, f, "call %d must carry fast=true (no promotion to careful on retry)", i)
	}
}
