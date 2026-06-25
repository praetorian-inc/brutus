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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// stickyPositiveResult returns a sticky-keys result with Success=true,
// simulating a confirmed sticky-keys backdoor.
func stickyPositiveResult(target string) *brutus.Result {
	return &brutus.Result{
		Protocol: "rdp",
		Target:   target,
		Username: "(sticky-keys)",
		ScanType: "sticky_keys",
		Success:  true,
		Banner:   "[CRITICAL] Sticky keys backdoor CONFIRMED",
	}
}

// stickyCleanResult returns a sticky-keys result with Success=false, Indeterminate=false,
// simulating a clean (no backdoor) sticky-keys check.
func stickyCleanResult(target string) *brutus.Result {
	return &brutus.Result{
		Protocol:      "rdp",
		Target:        target,
		Username:      "(sticky-keys)",
		ScanType:      "sticky_keys",
		Success:       false,
		Indeterminate: false,
	}
}

// utilmanPositiveResult returns a utilman result with Success=true,
// simulating a confirmed utilman backdoor.
func utilmanPositiveResult(target string) *brutus.Result {
	return &brutus.Result{
		Protocol: "rdp",
		Target:   target,
		Username: "(utilman)",
		ScanType: "utilman",
		Success:  true,
		Banner:   "[CRITICAL] Utilman backdoor CONFIRMED",
	}
}

// utilmanCleanResult returns a utilman result with Success=false, Indeterminate=false,
// simulating a clean (no backdoor) utilman check.
func utilmanCleanResult(target string) *brutus.Result {
	return &brutus.Result{
		Protocol:      "rdp",
		Target:        target,
		Username:      "(utilman)",
		ScanType:      "utilman",
		Success:       false,
		Indeterminate: false,
	}
}

// withDetectSeams replaces detectSticky and detectUtilman with the provided
// fakes for the duration of the test, restoring the originals via t.Cleanup.
func withDetectSeams(
	t *testing.T,
	stickyFn func(ctx context.Context, target string, connectTimeout, timeout time.Duration, username string, noVision, fast bool) *brutus.Result,
	utilmanFn func(ctx context.Context, target string, connectTimeout, timeout time.Duration, username string, noVision, fast bool) *brutus.Result,
) {
	t.Helper()
	origSticky := detectSticky
	origUtilman := detectUtilman
	detectSticky = stickyFn
	detectUtilman = utilmanFn
	t.Cleanup(func() {
		detectSticky = origSticky
		detectUtilman = origUtilman
	})
}

// TestRunDetection_ChecksSelector verifies that the checks selector routes
// execution to the correct subset of the sticky/utilman fakes:
//
//   - CheckStickyKeys → only detectSticky invoked; returns exactly 1 result.
//   - CheckUtilman    → only detectUtilman invoked; returns exactly 1 result.
//   - CheckBoth       → both invoked, sticky-first; returns exactly 2 results.
//
// These tests are RED until the developer adds:
//
//	type Check int
//	const CheckBoth Check = 0
//	const CheckStickyKeys Check = 1 (or iota)
//	const CheckUtilman Check = 2 (or iota)
//
// and updates runDetection to accept a trailing Check parameter.
func TestRunDetection_ChecksSelector(t *testing.T) {
	const target = "host:3389"
	const timeout = 5 * time.Second

	t.Run("CheckStickyKeys_OnlyStickyInvoked", func(t *testing.T) {
		var stickyInvoked, utilmanInvoked bool

		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				stickyInvoked = true
				return stickyCleanResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				utilmanInvoked = true
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckStickyKeys, false)

		assert.True(t, stickyInvoked, "sticky fake must be called for CheckStickyKeys")
		assert.False(t, utilmanInvoked, "utilman fake must NOT be called for CheckStickyKeys")
		require.Len(t, results, 1, "CheckStickyKeys must produce exactly 1 result")
		assert.Equal(t, "sticky_keys", results[0].ScanType,
			"single result must be sticky_keys")
	})

	t.Run("CheckUtilman_OnlyUtilmanInvoked", func(t *testing.T) {
		var stickyInvoked, utilmanInvoked bool

		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				stickyInvoked = true
				return stickyCleanResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				utilmanInvoked = true
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckUtilman, false)

		assert.False(t, stickyInvoked, "sticky fake must NOT be called for CheckUtilman")
		assert.True(t, utilmanInvoked, "utilman fake must be called for CheckUtilman")
		require.Len(t, results, 1, "CheckUtilman must produce exactly 1 result")
		assert.Equal(t, "utilman", results[0].ScanType,
			"single result must be utilman")
	})

	t.Run("CheckBoth_BothInvoked_StickyFirst", func(t *testing.T) {
		var invocationOrder []string

		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				invocationOrder = append(invocationOrder, "sticky")
				return stickyCleanResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				invocationOrder = append(invocationOrder, "utilman")
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, invocationOrder, 2, "both fakes must be invoked for CheckBoth")
		assert.Equal(t, "sticky", invocationOrder[0], "sticky must run first")
		assert.Equal(t, "utilman", invocationOrder[1], "utilman must run second")
		require.Len(t, results, 2, "CheckBoth must produce exactly 2 results")
		assert.Equal(t, "sticky_keys", results[0].ScanType, "results[0] must be sticky_keys")
		assert.Equal(t, "utilman", results[1].ScanType, "results[1] must be utilman")
	})
}

// TestRunDetection_ContaminationDowngrade verifies the contamination-aware
// utilman downgrade logic in CheckBoth mode:
//
//  1. sticky positive + utilman clean → utilman becomes Indeterminate=true,
//     banner mentions "rerun" and "utilman".
//  2. sticky clean + utilman clean → no downgrade; both remain clean.
//  3. sticky positive + utilman positive → no downgrade; utilman stays Success=true.
//  4. CheckUtilman single mode with clean utilman → no downgrade (no sticky context).
//
// These tests are RED until the developer implements the contamination-aware
// downgrade inside runDetection's CheckBoth branch (T2 in the plan).
func TestRunDetection_ContaminationDowngrade(t *testing.T) {
	const target = "host:3389"
	const timeout = 5 * time.Second

	t.Run("StickyPositive_UtilmanClean_Downgrades", func(t *testing.T) {
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return stickyPositiveResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, results, 2)
		// Sticky: still positive (never downgraded).
		assert.True(t, results[0].Success, "sticky result must remain Success=true")
		assert.False(t, results[0].Indeterminate, "sticky result must not become Indeterminate")

		// Utilman: downgraded to Indeterminate.
		assert.True(t, results[1].Indeterminate,
			"utilman result must be downgraded to Indeterminate when sticky is positive and utilman is clean")
		assert.False(t, results[1].Success,
			"utilman result must not be Success after downgrade")

		// Banner must carry both "rerun" and "utilman" (per the plan spec).
		assert.True(t,
			strings.Contains(results[1].Banner, "rerun") || strings.Contains(results[1].Banner, "rerun:"),
			"downgraded utilman banner must mention rerun, got: %q", results[1].Banner)
		assert.Contains(t, strings.ToLower(results[1].Banner), "utilman",
			"downgraded utilman banner must mention utilman")
	})

	t.Run("StickyClean_UtilmanClean_NoDowngrade", func(t *testing.T) {
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return stickyCleanResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, results, 2)
		assert.False(t, results[0].Indeterminate, "sticky must remain clean")
		assert.False(t, results[0].Success, "sticky must remain non-positive")
		assert.False(t, results[1].Indeterminate,
			"utilman must NOT be downgraded when sticky is also clean")
		assert.False(t, results[1].Success, "utilman must remain clean")
	})

	t.Run("StickyPositive_UtilmanPositive_NoDowngrade", func(t *testing.T) {
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return stickyPositiveResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return utilmanPositiveResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, results, 2)
		assert.True(t, results[0].Success, "sticky must remain Success=true")
		assert.True(t, results[1].Success,
			"utilman must NOT be downgraded when it is a positive — positives are never downgraded")
		assert.False(t, results[1].Indeterminate, "utilman must not become Indeterminate")
	})

	t.Run("CheckUtilman_SingleMode_NoDowngrade", func(t *testing.T) {
		// In single-utilman mode there is no preceding sticky check, so the
		// contamination condition can never apply — clean must stay clean.
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				// sticky fake should not even be called in CheckUtilman mode, but
				// provide it defensively.
				return stickyPositiveResult(tgt)
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, username string, noVision, fast bool) *brutus.Result {
				return utilmanCleanResult(tgt)
			},
		)

		results, _ := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckUtilman, false)

		require.Len(t, results, 1, "CheckUtilman must return exactly 1 result")
		assert.Equal(t, "utilman", results[0].ScanType)
		assert.False(t, results[0].Indeterminate,
			"single-mode utilman result must NOT be downgraded (no sticky context)")
		assert.False(t, results[0].Success, "clean utilman result must remain clean")
	})
}
