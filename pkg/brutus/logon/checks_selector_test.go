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

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
)

// The check fakes below return rdp.CheckOutcome, the typed detection-layer
// shape. They no longer fabricate a credential result: there is no username to
// invent and no banner to phrase, only a verdict.

// stickyPositiveOutcome simulates a confirmed sticky-keys backdoor.
func stickyPositiveOutcome() *rdp.CheckOutcome {
	return &rdp.CheckOutcome{
		Check: rdp.BackdoorStickyKeys, Performed: true, Stabilized: true,
		Verdict: "backdoor_confirmed", Confidence: 0.95,
	}
}

// stickyCleanOutcome simulates a clean sticky-keys check.
func stickyCleanOutcome() *rdp.CheckOutcome {
	return &rdp.CheckOutcome{
		Check: rdp.BackdoorStickyKeys, Performed: true, Stabilized: true,
		Verdict: "clean",
	}
}

// utilmanPositiveOutcome simulates a confirmed utilman backdoor.
func utilmanPositiveOutcome() *rdp.CheckOutcome {
	return &rdp.CheckOutcome{
		Check: rdp.BackdoorUtilman, Performed: true, Stabilized: true,
		Verdict: "backdoor_confirmed", Confidence: 0.95,
	}
}

// utilmanCleanOutcome simulates a clean utilman check.
func utilmanCleanOutcome() *rdp.CheckOutcome {
	return &rdp.CheckOutcome{
		Check: rdp.BackdoorUtilman, Performed: true, Stabilized: true,
		Verdict: "clean",
	}
}

// withDetectSeams replaces detectSticky and detectUtilman with the provided
// fakes for the duration of the test, restoring the originals via t.Cleanup.
func withDetectSeams(
	t *testing.T,
	stickyFn func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome,
	utilmanFn func(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *rdp.CheckOutcome,
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
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				stickyInvoked = true
				return stickyCleanOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				utilmanInvoked = true
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckStickyKeys, false)

		assert.True(t, stickyInvoked, "sticky fake must be called for CheckStickyKeys")
		assert.False(t, utilmanInvoked, "utilman fake must NOT be called for CheckStickyKeys")
		require.Len(t, findings, 1, "CheckStickyKeys must produce exactly 1 result")
		assert.Equal(t, BackdoorStickyKeys, findings[0].Check,
			"single result must be sticky_keys")
	})

	t.Run("CheckUtilman_OnlyUtilmanInvoked", func(t *testing.T) {
		var stickyInvoked, utilmanInvoked bool

		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				stickyInvoked = true
				return stickyCleanOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				utilmanInvoked = true
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckUtilman, false)

		assert.False(t, stickyInvoked, "sticky fake must NOT be called for CheckUtilman")
		assert.True(t, utilmanInvoked, "utilman fake must be called for CheckUtilman")
		require.Len(t, findings, 1, "CheckUtilman must produce exactly 1 result")
		assert.Equal(t, BackdoorUtilman, findings[0].Check,
			"single result must be utilman")
	})

	t.Run("CheckBoth_BothInvoked_StickyFirst", func(t *testing.T) {
		var invocationOrder []string

		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				invocationOrder = append(invocationOrder, "sticky")
				return stickyCleanOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				invocationOrder = append(invocationOrder, "utilman")
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, invocationOrder, 2, "both fakes must be invoked for CheckBoth")
		assert.Equal(t, "sticky", invocationOrder[0], "sticky must run first")
		assert.Equal(t, "utilman", invocationOrder[1], "utilman must run second")
		require.Len(t, findings, 2, "CheckBoth must produce exactly 2 results")
		assert.Equal(t, BackdoorStickyKeys, findings[0].Check, "results[0] must be sticky_keys")
		assert.Equal(t, BackdoorUtilman, findings[1].Check, "results[1] must be utilman")
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
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return stickyPositiveOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, findings, 2)
		// Sticky: still positive (never downgraded).
		assert.True(t, findings[0].Verdict.Positive(), "sticky result must remain Success=true")
		assert.NotEqual(t, VerdictIndeterminate, findings[0].Verdict, "sticky result must not become Indeterminate")

		// Utilman: downgraded to Indeterminate.
		assert.Equal(t, VerdictIndeterminate, findings[1].Verdict,
			"utilman result must be downgraded to Indeterminate when sticky is positive and utilman is clean")
		assert.False(t, findings[1].Verdict.Positive(),
			"utilman result must not be Success after downgrade")

		// The reason for the downgrade travels as typed diagnostics, not as a
		// banner a consumer would have to parse.
		assert.Contains(t, findings[1].Diagnostics.SkipReason, "rerun",
			"downgraded utilman finding must tell the operator to rerun, got: %q", findings[1].Diagnostics.SkipReason)
		assert.Contains(t, strings.ToLower(findings[1].Diagnostics.SkipReason), "utilman",
			"downgraded utilman finding must name the check to rerun")
		assert.Zero(t, findings[1].Confidence,
			"a downgraded reading carries no confidence")
	})

	t.Run("StickyClean_UtilmanClean_NoDowngrade", func(t *testing.T) {
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return stickyCleanOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, findings, 2)
		assert.NotEqual(t, VerdictIndeterminate, findings[0].Verdict, "sticky must remain clean")
		assert.False(t, findings[0].Verdict.Positive(), "sticky must remain non-positive")
		assert.NotEqual(t, VerdictIndeterminate, findings[1].Verdict,
			"utilman must NOT be downgraded when sticky is also clean")
		assert.False(t, findings[1].Verdict.Positive(), "utilman must remain clean")
	})

	t.Run("StickyPositive_UtilmanPositive_NoDowngrade", func(t *testing.T) {
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return stickyPositiveOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return utilmanPositiveOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckBoth, false)

		require.Len(t, findings, 2)
		assert.True(t, findings[0].Verdict.Positive(), "sticky must remain Success=true")
		assert.True(t, findings[1].Verdict.Positive(),
			"utilman must NOT be downgraded when it is a positive — positives are never downgraded")
		assert.NotEqual(t, VerdictIndeterminate, findings[1].Verdict, "utilman must not become Indeterminate")
	})

	t.Run("CheckUtilman_SingleMode_NoDowngrade", func(t *testing.T) {
		// In single-utilman mode there is no preceding sticky check, so the
		// contamination condition can never apply — clean must stay clean.
		withDetectSeams(t,
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				// sticky fake should not even be called in CheckUtilman mode, but
				// provide it defensively.
				return stickyPositiveOutcome()
			},
			func(ctx context.Context, tgt string, connectTimeout, to time.Duration, noVision, fast bool) *rdp.CheckOutcome {
				return utilmanCleanOutcome()
			},
		)

		findings := runDetection(context.Background(), target, 3*time.Second, timeout, false, CheckUtilman, false)

		require.Len(t, findings, 1, "CheckUtilman must return exactly 1 result")
		assert.Equal(t, BackdoorUtilman, findings[0].Check)
		assert.NotEqual(t, VerdictIndeterminate, findings[0].Verdict,
			"single-mode utilman result must NOT be downgraded (no sticky context)")
		assert.False(t, findings[0].Verdict.Positive(), "clean utilman result must remain clean")
	})
}
