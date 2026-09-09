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
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
		detectionInvoked.Store(true)
		return nil
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call — Acquire must fail immediately

	findings := DetectBackdoors(ctx, "1.2.3.4:3389", 3*time.Second, 5*time.Second, false, 0, CheckBoth, "", false, false)

	// The host never ran; both findings must read as cancelled.
	require.Len(t, findings, 2, "canceled context must produce exactly 2 findings (sticky + utilman)")
	assert.False(t, AnyPositive(findings), "no scan ran; nothing can be positive")

	for i := range findings {
		assert.Equal(t, VerdictCancelled, findings[i].Verdict, "findings[%d] must be cancelled (never ran)", i)
		assert.True(t, findings[i].Verdict.NeedsRerun(), "findings[%d] must be a rerun candidate", i)
		assert.False(t, findings[i].Verdict.Scanned(), "findings[%d] never produced a reading", i)
	}

	// The detection body must NEVER have been called — cancellation must
	// short-circuit before any RDP work begins.
	assert.False(t, detectionInvoked.Load(),
		"runDetection must not be invoked when context is canceled before Acquire")
}

// TestCancelledResults verifies the content of the CancelledResults helper: one
// finding per selected check, each carrying the cancelled verdict and a reason.
// Content, not just length — a length-only assertion would miss a regression
// that reported a host that never ran as clean.
func TestCancelledResults(t *testing.T) {
	const target = "1.2.3.4:3389"

	findings := CancelledResults(target, CheckBoth)

	require.Len(t, findings, 2, "CheckBoth must produce sticky + utilman")
	sticky, utilman := findings[0], findings[1]

	assert.Equal(t, BackdoorStickyKeys, sticky.Check, "first finding must be sticky keys")
	assert.Equal(t, BackdoorUtilman, utilman.Check, "second finding must be utilman")

	for _, f := range findings {
		assert.Equal(t, target, f.Target)
		assert.Equal(t, VerdictCancelled, f.Verdict)
		assert.True(t, f.Verdict.NeedsRerun(), "a cancelled host must be rerun")
		assert.False(t, f.Verdict.Scanned(), "a cancelled host produced no reading")
		assert.False(t, f.Verdict.Positive())
		assert.Contains(t, f.Diagnostics.SkipReason, "canceled",
			"the reason the host was not scanned must reach the operator")
	}
}

// TestCancelledResults_RespectsSelector pins that the cancelled path reports
// the same checks the scan would have run. It previously always returned both,
// so a cancelled "brutus stickykeys" scan invented a utilman result.
func TestCancelledResults_RespectsSelector(t *testing.T) {
	sticky := CancelledResults("h:3389", CheckStickyKeys)
	require.Len(t, sticky, 1)
	assert.Equal(t, BackdoorStickyKeys, sticky[0].Check)

	utilman := CancelledResults("h:3389", CheckUtilman)
	require.Len(t, utilman, 1)
	assert.Equal(t, BackdoorUtilman, utilman[0].Check)
}
