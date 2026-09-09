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

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// withScanTargetFn swaps the package-level scanTargetFn seam for the duration of
// a test and restores the original via the returned cleanup function.
func withScanTargetFn(t *testing.T, fn func(ctx context.Context, target string, base *runConfig) []logon.Finding) {
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
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		return []logon.Finding{
			{Target: target, Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictClean},
			{Target: target, Check: logon.BackdoorUtilman, Verdict: logon.VerdictClean},
		}
	})

	targets := []string{"a:3389", "b:3389", "c:3389", "d:3389", "e:3389"}
	base := &runConfig{baseConfigOptions: &baseConfigOptions{threads: 3}}

	findings := runScanTargetsConcurrent(targets, base)

	// Two results per target, flattened in input order.
	expectedOrder := []string{
		"a:3389", "a:3389",
		"b:3389", "b:3389",
		"c:3389", "c:3389",
		"d:3389", "d:3389",
		"e:3389", "e:3389",
	}
	actualOrder := make([]string, len(findings))
	for i := range findings {
		actualOrder[i] = findings[i].Target
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

	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		n := current.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return []logon.Finding{{Target: target, Verdict: logon.VerdictClean}}
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

// TestRunScanTargetsConcurrent_AggregatesPositives verifies that a positive on
// any single target is visible in the aggregated findings. This replaces the
// old hasSuccess bool: "did anything turn up" is now derived from the verdicts
// rather than threaded alongside them, so it cannot disagree with them.
func TestRunScanTargetsConcurrent_AggregatesPositives(t *testing.T) {
	base := &runConfig{baseConfigOptions: &baseConfigOptions{threads: 4}}
	targets := []string{"a:3389", "b:3389", "c:3389"}

	// No target has a backdoor.
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		return []logon.Finding{{Target: target, Verdict: logon.VerdictClean}}
	})
	assert.False(t, logon.AnyPositive(runScanTargetsConcurrent(targets, base)),
		"no target has a backdoor")

	// Exactly one target (b) has one.
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		v := logon.VerdictClean
		if target == "b:3389" {
			v = logon.VerdictBackdoorConfirmed
		}
		return []logon.Finding{{Target: target, Verdict: v}}
	})
	assert.True(t, logon.AnyPositive(runScanTargetsConcurrent(targets, base)),
		"one target has a backdoor")

	// A non-NLA host whose trigger produced the normal dialog is NOT a positive.
	// The old bool reported exactly this case as success.
	withScanTargetFn(t, func(_ context.Context, target string, _ *runConfig) []logon.Finding {
		return []logon.Finding{{Target: target, Verdict: logon.VerdictNoBackdoor}}
	})
	assert.False(t, logon.AnyPositive(runScanTargetsConcurrent(targets, base)),
		"no_backdoor means the check ran and found nothing; it is never a positive")
}
