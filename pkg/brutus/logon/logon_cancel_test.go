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

// TestDetectBackdoors_CancelledWhileQueued verifies the cardinal-property
// protection at the admission-control gate: when the context is already
// canceled before DetectBackdoors is called, the semaphore Acquire fails and
// the host must read as INDETERMINATE — never silently clean or empty.
//
// This covers the previously-uncovered branch at logon.go:50-53.
func TestDetectBackdoors_CancelledWhileQueued(t *testing.T) {
	// Use the minimum semaphore size (1 slot) so Acquire is always attempted,
	// giving us a deterministic canceled-acquire on the pre-canceled context.
	withDecodeSlots(t, 1)

	// Swap runDetection with a fake that records whether it was ever invoked.
	// The cardinal property requires it is NOT invoked when the ctx is canceled
	// before the Acquire — the host never ran, so no detection work happens.
	// Stub the NLA probe to return NegoScannable. The canceled context causes the
	// decode-slot Acquire to fail before runDetection is ever called, so we need the
	// probe stub to ensure the probe itself also receives the canceled context.
	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}

	var detectionInvoked atomic.Bool
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
		detectionInvoked.Store(true)
		return []brutus.Result{}, false
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call — Acquire must fail immediately

	results, hasSuccess := DetectBackdoors(ctx, "1.2.3.4:3389", 3*time.Second, 5*time.Second, false, 0, CheckBoth, "", false, false)

	// The host never ran; both results must be INDETERMINATE.
	require.Len(t, results, 2, "canceled context must produce exactly 2 results (sticky + utilman)")
	assert.False(t, hasSuccess, "no scan ran; hasSuccess must be false")

	for i, r := range results {
		assert.True(t, r.Indeterminate, "result[%d] must be Indeterminate (never ran)", i)
		assert.False(t, r.Success, "result[%d] must not be Success (never ran)", i)
	}

	// The detection body must NEVER have been called — cancellation must
	// short-circuit before any RDP work begins.
	assert.False(t, detectionInvoked.Load(),
		"runDetection must not be invoked when context is canceled before Acquire")
}

// TestCancelledResults verifies the full content of the CancelledResults helper:
// 2 results, correct ScanType/username/protocol/target/Indeterminate/Success,
// and banners that carry both "INDETERMINATE" and "canceled" (the rerun signal).
// Testing content (not just length) satisfies the avoiding-low-value-tests
// requirement — length-only assertions would miss a regression that drops
// Indeterminate: true.
func TestCancelledResults(t *testing.T) {
	const target = "1.2.3.4:3389"

	results := CancelledResults(target)

	require.Len(t, results, 2, "CancelledResults must return exactly 2 results (sticky + utilman)")

	sticky := results[0]
	utilman := results[1]

	// Structural: ScanType distinguishes the two checks.
	assert.Equal(t, "sticky_keys", sticky.ScanType, "first result must be sticky_keys")
	assert.Equal(t, "utilman", utilman.ScanType, "second result must be utilman")

	// Usernames match the strings used by the real detection path.
	assert.Equal(t, "(sticky-keys)", sticky.Username, "sticky username must be (sticky-keys)")
	assert.Equal(t, "(utilman)", utilman.Username, "utilman username must be (utilman)")

	// Both results must identify the target host and protocol.
	assert.Equal(t, target, sticky.Target, "sticky Target must equal input target")
	assert.Equal(t, target, utilman.Target, "utilman Target must equal input target")
	assert.Equal(t, "rdp", sticky.Protocol, "sticky Protocol must be rdp")
	assert.Equal(t, "rdp", utilman.Protocol, "utilman Protocol must be rdp")

	// Cardinal-property assertions: both must be INDETERMINATE and not Success.
	assert.True(t, sticky.Indeterminate, "sticky result must be Indeterminate")
	assert.True(t, utilman.Indeterminate, "utilman result must be Indeterminate")
	assert.False(t, sticky.Success, "sticky result must not be Success")
	assert.False(t, utilman.Success, "utilman result must not be Success")

	// Banners must carry both "INDETERMINATE" (cardinal signal) and "canceled"
	// (the rerun signal that tells the operator why the host was not scanned).
	assert.Contains(t, sticky.Banner, "INDETERMINATE",
		"sticky banner must contain INDETERMINATE")
	assert.Contains(t, sticky.Banner, "canceled",
		"sticky banner must contain canceled (rerun signal)")
	assert.Contains(t, utilman.Banner, "INDETERMINATE",
		"utilman banner must contain INDETERMINATE")
	assert.Contains(t, utilman.Banner, "canceled",
		"utilman banner must contain canceled (rerun signal)")
}
