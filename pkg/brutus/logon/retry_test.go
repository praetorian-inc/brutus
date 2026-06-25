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

// indeterminateResults returns a pair of results (sticky+utilman) both marked
// Indeterminate, simulating a stabilization failure (e.g. CPU-starved render).
func indeterminateResults(target string) ([]brutus.Result, bool) {
	return []brutus.Result{
		{Target: target, ScanType: "sticky_keys", Indeterminate: true,
			Banner: "[WARN] Sticky keys check INDETERMINATE (render did not stabilize — rerun)"},
		{Target: target, ScanType: "utilman", Indeterminate: true,
			Banner: "[WARN] Utilman check INDETERMINATE (render did not stabilize — rerun)"},
	}, false
}

// cleanResults returns a pair of results (sticky+utilman) both clean (not
// indeterminate, no backdoor found) — simulating a stabilized, negative render.
func cleanResults(target string) ([]brutus.Result, bool) {
	return []brutus.Result{
		{Target: target, ScanType: "sticky_keys", Indeterminate: false},
		{Target: target, ScanType: "utilman", Indeterminate: false},
	}, false
}

// foundResults returns a pair of results where the sticky check indicates a
// backdoor was found (hasSuccess=true).
func foundResults(target string) ([]brutus.Result, bool) {
	return []brutus.Result{
		{Target: target, ScanType: "sticky_keys", Indeterminate: false, Success: true,
			Banner: "[CRITICAL] Sticky keys backdoor confirmed"},
		{Target: target, ScanType: "utilman", Indeterminate: false},
	}, true
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
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
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

	results, hasSuccess := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, results, 2, "expected 2 results (sticky + utilman)")
	assert.Equal(t, int32(2), attempts.Load(), "expected exactly 2 attempts: indeterminate on 0, clean on 1")
	assert.False(t, hasSuccess, "no backdoor found")
	assert.False(t, results[0].Indeterminate, "final sticky result must not be indeterminate")
	assert.False(t, results[1].Indeterminate, "final utilman result must not be indeterminate")
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
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
		attempts.Add(1)
		return foundResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	results, hasSuccess := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, results, 2)
	assert.Equal(t, int32(1), attempts.Load(), "backdoor found: must not retry (exactly 1 attempt)")
	assert.True(t, hasSuccess, "backdoor found, hasSuccess must be true")
	assert.True(t, results[0].Success, "sticky result must carry Success=true")
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
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
		attempts.Add(1)
		return cleanResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	results, hasSuccess := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, 2, CheckBoth, "", false, false)

	require.Len(t, results, 2)
	assert.Equal(t, int32(1), attempts.Load(), "clean non-indeterminate: must not retry (exactly 1 attempt)")
	assert.False(t, hasSuccess)
	assert.False(t, results[0].Indeterminate)
	assert.False(t, results[1].Indeterminate)
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
	runDetection = func(ctx context.Context, tgt string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
		attempts.Add(1)
		return indeterminateResults(tgt)
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	results, hasSuccess := DetectBackdoors(context.Background(), target, 3*time.Second, 5*time.Second, false, maxRetries, CheckBoth, "", false, false)

	require.Len(t, results, 2)
	assert.Equal(t, int32(maxRetries+1), attempts.Load(),
		"always-indeterminate: attempts must equal maxRetries+1 (%d)", maxRetries+1)
	assert.False(t, hasSuccess, "no backdoor found even after all retries")
	// The final result is still indeterminate — caller must surface this to the user.
	assert.True(t, results[0].Indeterminate, "final result still indeterminate after cap")
	assert.True(t, results[1].Indeterminate, "final result still indeterminate after cap")
}
