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

package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// TestRunScanTargetsConcurrent_CancelledTargetsStillReport verifies that every
// target emits a non-nil, canceled finding when the context is already
// canceled on entry — no target may silently vanish when the run is canceled
// (invariant I5/I6).
func TestRunScanTargetsConcurrent_CancelledTargetsStillReport(t *testing.T) {
	// Install a scan fake that records invocations. The point of this test is
	// that the fake must NOT be called for any target — cancellation must
	// short-circuit before any per-target scan work begins.
	scanInvoked := false
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		scanInvoked = true
		return []logon.Finding{
			{Target: target, Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictClean},
			{Target: target, Check: logon.BackdoorUtilman, Verdict: logon.VerdictClean},
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so every goroutine sees ctx.Err() != nil immediately

	targets := []string{"10.0.0.1:3389", "10.0.0.2:3389"}
	base := &runConfig{baseConfigOptions: &baseConfigOptions{
		threads: 4,
		timeout: 5 * time.Second,
	}}

	findings := runScanTargetsConcurrentCtx(ctx, targets, base)

	// Every target must contribute findings — no silent nil/empty.
	require.NotNil(t, findings, "findings slice must not be nil")
	assert.Equal(t, len(targets)*2, len(findings),
		"each target must contribute exactly 2 findings (sticky + utilman)")

	// Every finding must read as canceled — the hosts never ran.
	for i := range findings {
		f := &findings[i]
		assert.Equal(t, logon.VerdictCanceled, f.Verdict,
			"findings[%d] (target %s) must be canceled (scan was canceled)", i, f.Target)
		assert.True(t, f.Verdict.NeedsRerun(),
			"findings[%d] must be a rerun candidate", i)
		assert.False(t, f.Verdict.Scanned(),
			"findings[%d] never produced a reading", i)
	}

	assert.False(t, logon.AnyPositive(findings), "a canceled scan cannot report a positive")
	assert.False(t, scanInvoked,
		"scanTargetFn must not be invoked when context is canceled before any target runs")
}
