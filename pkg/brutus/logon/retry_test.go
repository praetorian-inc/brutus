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

func noBackdoorResults(target string) []Finding {
	return []Finding{
		{Target: target, Check: BackdoorStickyKeys, Verdict: VerdictNoBackdoor, Confidence: 0.8},
		{Target: target, Check: BackdoorUtilman, Verdict: VerdictNoBackdoor, Confidence: 0.8},
	}
}

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
	assert.True(t, findings[0].Verdict.NeedsRerun(), "final result still indeterminate after cap")
	assert.True(t, findings[1].Verdict.NeedsRerun(), "final result still indeterminate after cap")
}
