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

func TestDetectBackdoors_CancelledWhileQueued(t *testing.T) {
	withDecodeSlots(t, 1)

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

	require.Len(t, findings, 2, "canceled context must produce exactly 2 findings (sticky + utilman)")
	assert.False(t, AnyPositive(findings), "no scan ran; nothing can be positive")

	for i := range findings {
		assert.Equal(t, VerdictCanceled, findings[i].Verdict, "findings[%d] must be canceled (never ran)", i)
		assert.True(t, findings[i].Verdict.NeedsRerun(), "findings[%d] must be a rerun candidate", i)
		assert.False(t, findings[i].Verdict.Scanned(), "findings[%d] never produced a reading", i)
	}

	assert.False(t, detectionInvoked.Load(),
		"runDetection must not be invoked when context is canceled before Acquire")
}

func TestCancelledResults(t *testing.T) {
	const target = "1.2.3.4:3389"

	findings := CancelledResults(target, CheckBoth)

	require.Len(t, findings, 2, "CheckBoth must produce sticky + utilman")
	sticky, utilman := findings[0], findings[1]

	assert.Equal(t, BackdoorStickyKeys, sticky.Check, "first finding must be sticky keys")
	assert.Equal(t, BackdoorUtilman, utilman.Check, "second finding must be utilman")

	for _, f := range findings {
		assert.Equal(t, target, f.Target)
		assert.Equal(t, VerdictCanceled, f.Verdict)
		assert.True(t, f.Verdict.NeedsRerun(), "a canceled host must be rerun")
		assert.False(t, f.Verdict.Scanned(), "a canceled host produced no reading")
		assert.False(t, f.Verdict.Positive())
		assert.Contains(t, f.Diagnostics.SkipReason, "canceled",
			"the reason the host was not scanned must reach the operator")
	}
}

func TestCancelledResults_RespectsSelector(t *testing.T) {
	sticky := CancelledResults("h:3389", CheckStickyKeys)
	require.Len(t, sticky, 1)
	assert.Equal(t, BackdoorStickyKeys, sticky[0].Check)

	utilman := CancelledResults("h:3389", CheckUtilman)
	require.Len(t, utilman, 1)
	assert.Equal(t, BackdoorUtilman, utilman[0].Check)
}
