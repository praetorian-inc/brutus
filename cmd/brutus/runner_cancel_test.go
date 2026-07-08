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

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// TestRunScanTargetsConcurrent_CancelledIndexIndeterminate verifies that every
// target emits non-nil, INDETERMINATE results when the context is already
// canceled on entry — no target may silently vanish (emit nil/empty results)
// when the run is canceled (invariant I5/I6).
//
// This test is RED until the developer adds an injectable-context entry point:
//
//	func runScanTargetsConcurrentCtx(ctx context.Context, targets []string, base *runConfig) ([]brutus.Result, bool)
//
// with the existing runScanTargetsConcurrent wrapping it via its own
// signal.NotifyContext.
func TestRunScanTargetsConcurrent_CancelledIndexIndeterminate(t *testing.T) {
	// Install a scan fake that records invocations. The point of this test is
	// that the fake must NOT be called for any target — cancellation must
	// short-circuit before any per-target scan work begins.
	scanInvoked := false
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) ([]brutus.Result, bool) {
		scanInvoked = true
		return []brutus.Result{
			{Target: target, ScanType: "sticky_keys"},
			{Target: target, ScanType: "utilman"},
		}, false
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so every goroutine sees ctx.Err() != nil immediately

	targets := []string{"10.0.0.1:3389", "10.0.0.2:3389"}
	base := &runConfig{baseConfigOptions: &baseConfigOptions{
		threads: 4,
		timeout: 5 * time.Second,
	}}

	results, hasSuccess := runScanTargetsConcurrentCtx(ctx, targets, base)

	// Every target must contribute results — no silent nil/empty.
	require.NotNil(t, results, "results slice must not be nil")
	assert.Equal(t, len(targets)*2, len(results),
		"each target must contribute exactly 2 results (sticky + utilman)")

	// Every result must be INDETERMINATE — hosts never ran.
	for i, r := range results {
		assert.True(t, r.Indeterminate,
			"result[%d] (target %s) must be Indeterminate (scan was canceled)", i, r.Target)
		assert.False(t, r.Success,
			"result[%d] must not be Success (scan was canceled)", i)
	}

	assert.False(t, hasSuccess, "canceled scan must not report success")
	assert.False(t, scanInvoked,
		"scanTargetFn must not be invoked when context is canceled before any target runs")
}
