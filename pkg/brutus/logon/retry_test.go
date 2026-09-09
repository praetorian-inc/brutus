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

// indeterminateResults returns a sticky+utilman pair that both reached no
// verdict, simulating a stabilization failure (e.g. CPU-starved render).
func indeterminateResults(target string) []Finding {
	return []Finding{
		{Target: target, Check: BackdoorStickyKeys, Verdict: VerdictIndeterminate},
		{Target: target, Check: BackdoorUtilman, Verdict: VerdictIndeterminate},
	}
}

// cleanResults returns a sticky+utilman pair that both read clean — a
// stabilized, negative render.
func cleanResults(target string) []Finding {
	return []Finding{
		{Target: target, Check: BackdoorStickyKeys, Verdict: VerdictClean},
		{Target: target, Check: BackdoorUtilman, Verdict: VerdictClean},
	}
}

// foundResults returns a pair where the sticky check found a backdoor.
func foundResults(target string) []Finding {
	return []Finding{
		{Target: target, Check: BackdoorStickyKeys, Verdict: VerdictBackdoorConfirmed, Confidence: 0.92},
		{Target: target, Check: BackdoorUtilman, Verdict: VerdictClean},
	}
}

// noBackdoorResults returns a pair where the sticky trigger produced the NORMAL
// Windows dialog on a non-NLA host. This is the state the old []brutus.Result
// API reported as Success=true; it must never be treated as a positive, and
// (being a real observation) must never be retried.
func noBackdoorResults(target string) []Finding {
	return []Finding{
		{Target: target, Check: BackdoorStickyKeys, Verdict: VerdictNoBackdoor, Confidence: 0.8},
		{Target: target, Check: BackdoorUtilman, Verdict: VerdictNoBackdoor, Confidence: 0.8},
	}
}

// TestDetectBackdoors_RetriesIndeterminate verifies that DetectBackdoors retries
// when the first attempt returns indeterminate results and stops when a
// non-indeterminate result is returned.
//
// Scenario: attempt 0 → indeterminate; attempt 1 → clean (non-indeterminate).
// With maxRetries=2 the loop allows up to 3 total attempts. It must stop at 2
// because the second attempt is no longer indeterminate.
func TestDetectBackdoors_RetriesIndeterminate(t *testing.T) {
	const target = "host:3389"

	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var attempts atomic.Int32
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		n := int(attempts.Add(1))
		if n == 1 {
			return indeterminateResults(tgt)
		}
		return cleanResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	findings := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, findings, 2, "expected 2 results (sticky + utilman)")
	assert.Equal(t, int32(2), attempts.Load(), "expected exactly 2 attempts: indeterminate on 0, clean on 1")
	assert.False(t, AnyPositive(findings), "no backdoor found")
	assert.False(t, findings[0].Verdict.NeedsRerun(), "final sticky result must not be indeterminate")
	assert.False(t, findings[1].Verdict.NeedsRerun(), "final utilman result must not be indeterminate")
}

// TestDetectBackdoors_NoRetryOnFoundBackdoor verifies that a positive (backdoor
// found) result on the first attempt is returned immediately without retrying.
// A found backdoor is a final verdict — retrying would be incorrect.
func TestDetectBackdoors_NoRetryOnFoundBackdoor(t *testing.T) {
	const target = "host:3389"

	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var attempts atomic.Int32
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		attempts.Add(1)
		return foundResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	findings := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, findings, 2)
	assert.Equal(t, int32(1), attempts.Load(), "backdoor found: must not retry (exactly 1 attempt)")
	assert.True(t, AnyPositive(findings), "backdoor found")
	assert.True(t, findings[0].Verdict.Positive(), "sticky finding must be a positive")
}

// TestDetectBackdoors_NoRetryOnStabilizedClean verifies that a stabilized clean
// result (non-indeterminate, no backdoor) on the first attempt is returned
// immediately without retrying. A stabilized clean is a final verdict.
func TestDetectBackdoors_NoRetryOnStabilizedClean(t *testing.T) {
	const target = "host:3389"

	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var attempts atomic.Int32
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		attempts.Add(1)
		return cleanResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	findings := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, findings, 2)
	assert.Equal(t, int32(1), attempts.Load(), "clean non-indeterminate: must not retry (exactly 1 attempt)")
	assert.False(t, AnyPositive(findings))
	assert.False(t, findings[0].Verdict.NeedsRerun())
	assert.False(t, findings[1].Verdict.NeedsRerun())
}

// TestDetectBackdoors_NoRetryOnNoBackdoor pins that the non-NLA reading is
// treated as the final observation it is.
//
// no_backdoor means the trigger fired and produced the normal Windows dialog:
// the check worked. A retry could come back indeterminate and would replace a
// real observation with nothing -- the false negative the cardinal rule
// forbids. It must also not be mistaken for a positive, which is exactly what
// the old Success bool did with this state.
func TestDetectBackdoors_NoRetryOnNoBackdoor(t *testing.T) {
	const target = "host:3389"

	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var attempts atomic.Int32
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		attempts.Add(1)
		return noBackdoorResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	findings := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, findings, 2)
	assert.Equal(t, int32(1), attempts.Load(),
		"no_backdoor is a real observation: it must not be retried")
	assert.False(t, AnyPositive(findings),
		"a host with no backdoor must never aggregate as a positive")
	assert.False(t, AnyNeedsRerun(findings))
	for i := range findings {
		assert.True(t, findings[i].Verdict.Scanned(),
			"findings[%d] reached a real reading", i)
	}
}

// TestDetectBackdoors_AttemptCap verifies that when every attempt returns
// indeterminate, DetectBackdoors stops after exactly maxRetries+1 total attempts
// and returns the final (still-indeterminate) result.
//
// With maxRetries=2: allowed attempts = 3. The last result is returned even
// though it is still indeterminate.
func TestDetectBackdoors_AttemptCap(t *testing.T) {
	const target = "host:3389"
	const maxRetries = 2

	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}
	var attempts atomic.Int32
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		attempts.Add(1)
		return indeterminateResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	findings := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, maxRetries, CheckBoth, "", false, false)

	require.Len(t, findings, 2)
	assert.Equal(t, int32(maxRetries+1), attempts.Load(),
		"always-indeterminate: attempts must equal maxRetries+1 (%d)", maxRetries+1)
	assert.False(t, AnyPositive(findings), "no backdoor found even after all retries")
	// The final result is still indeterminate — caller must surface this to the user.
	assert.True(t, findings[0].Verdict.NeedsRerun(), "final result still indeterminate after cap")
	assert.True(t, findings[1].Verdict.NeedsRerun(), "final result still indeterminate after cap")
}
