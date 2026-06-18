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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// withScanTargetFn swaps the package-level scanTargetFn seam for the duration of
// a test and restores the original via the returned cleanup function.
func withScanTargetFn(t *testing.T, fn func(ctx context.Context, target string, base *runConfig) ([]brutus.Result, bool)) {
	t.Helper()
	orig := scanTargetFn
	scanTargetFn = fn
	t.Cleanup(func() { scanTargetFn = orig })
}

// TestRunScanTargetsConcurrent_PreservesInputOrder verifies that results are
// aggregated in the same order as the input targets, regardless of which
// goroutine finishes first. Each fake scan returns two results (mirroring the
// real sticky-keys + utilman pair) so we assert the flattened order.
func TestRunScanTargetsConcurrent_PreservesInputOrder(t *testing.T) {
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) ([]brutus.Result, bool) {
		return []brutus.Result{
			{Target: target, ScanType: "sticky_keys"},
			{Target: target, ScanType: "utilman"},
		}, false
	})

	targets := []string{"a:3389", "b:3389", "c:3389", "d:3389", "e:3389"}
	base := &runConfig{baseConfigOptions: &baseConfigOptions{threads: 3}}

	results, _ := runScanTargetsConcurrent(targets, base)

	// Two results per target, flattened in input order.
	expectedOrder := []string{
		"a:3389", "a:3389",
		"b:3389", "b:3389",
		"c:3389", "c:3389",
		"d:3389", "d:3389",
		"e:3389", "e:3389",
	}
	actualOrder := make([]string, len(results))
	for i := range results {
		actualOrder[i] = results[i].Target
	}
	assert.Equal(t, expectedOrder, actualOrder)
}

// TestRunScanTargetsConcurrent_BoundedByThreads verifies that concurrency is
// bounded by base.threads and that parallelism actually occurs. We track peak
// observed concurrency with an atomic counter incremented on entry and
// decremented on exit, with a small sleep to force overlap.
func TestRunScanTargetsConcurrent_BoundedByThreads(t *testing.T) {
	const threads = 5

	var current, peak atomic.Int32

	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) ([]brutus.Result, bool) {
		n := current.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return []brutus.Result{{Target: target}}, false
	})

	targets := make([]string, 20)
	for i := range targets {
		targets[i] = "host:3389"
	}
	base := &runConfig{baseConfigOptions: &baseConfigOptions{threads: threads}}

	runScanTargetsConcurrent(targets, base)

	observed := int(peak.Load())
	// Never exceed the configured limit, and prove real parallelism occurred.
	assert.LessOrEqual(t, observed, threads, "peak concurrency must not exceed threads")
	assert.GreaterOrEqual(t, observed, 2, "expected parallel execution, not serial")
}

// TestRunScanTargetsConcurrent_HasSuccess verifies hasSuccess is true iff at
// least one fake scan reports success.
func TestRunScanTargetsConcurrent_HasSuccess(t *testing.T) {
	base := &runConfig{baseConfigOptions: &baseConfigOptions{threads: 4}}
	targets := []string{"a:3389", "b:3389", "c:3389"}

	// No target succeeds.
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) ([]brutus.Result, bool) {
		return []brutus.Result{{Target: target}}, false
	})
	_, hasSuccess := runScanTargetsConcurrent(targets, base)
	assert.False(t, hasSuccess, "no target succeeded, hasSuccess must be false")

	// Exactly one target (b) succeeds.
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) ([]brutus.Result, bool) {
		return []brutus.Result{{Target: target}}, target == "b:3389"
	})
	_, hasSuccess = runScanTargetsConcurrent(targets, base)
	assert.True(t, hasSuccess, "one target succeeded, hasSuccess must be true")
}
