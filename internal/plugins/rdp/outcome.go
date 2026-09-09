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

package rdp

import (
	"context"
	"time"
)

// CheckOutcome is the typed outcome of one logon-screen check, normalized
// across the two structurally identical per-check result types so callers
// outside this package convert one shape instead of two.
//
// It carries no banner and no Success bool: the verdict stays a value all the
// way out to pkg/brutus/logon, which is what lets consumers stop parsing prose.
type CheckOutcome struct {
	// Check is which accessibility binary was triggered.
	Check BackdoorType
	// Performed reports whether the check actually ran to an analysis.
	Performed bool
	// Stabilized reports whether both frame pumps settled.
	Stabilized bool
	// Unreachable is set only when the TCP dial itself failed. It separates a
	// terminally unreachable host from the other !Performed failures, which are
	// rerun candidates.
	Unreachable bool
	// SkipReason explains a check that did not run.
	SkipReason string
	// Verdict is the raw verdict string from the analysis layer.
	Verdict string
	// Confidence is the analysis confidence, 0.0-1.0.
	Confidence float64
	// Heuristic, Vision and RegionNote are the operator-facing diagnostics
	// behind Verdict. RegionNote never changes the verdict.
	Heuristic  string
	Vision     string
	RegionNote string
	// SessionTerminated records a server-side teardown mid-scan, with the
	// reason it reported.
	SessionTerminated bool
	TerminationReason string
}

// stickyOutcome normalizes a sticky-keys result.
func stickyOutcome(r *StickyKeysResult) *CheckOutcome {
	return &CheckOutcome{
		Check:             BackdoorStickyKeys,
		Performed:         r.Performed,
		Stabilized:        r.Stabilized,
		Unreachable:       r.Unreachable,
		SkipReason:        r.SkipReason,
		Verdict:           r.OverallVerdict,
		Confidence:        r.Confidence,
		Heuristic:         r.HeuristicResult,
		Vision:            r.VisionResult,
		RegionNote:        r.RegionNote,
		SessionTerminated: r.SessionTerminated,
		TerminationReason: r.TerminationReason,
	}
}

// utilmanOutcome normalizes a utilman result.
func utilmanOutcome(r *UtilmanResult) *CheckOutcome {
	return &CheckOutcome{
		Check:             BackdoorUtilman,
		Performed:         r.Performed,
		Stabilized:        r.Stabilized,
		Unreachable:       r.Unreachable,
		SkipReason:        r.SkipReason,
		Verdict:           r.OverallVerdict,
		Confidence:        r.Confidence,
		Heuristic:         r.HeuristicResult,
		Vision:            r.VisionResult,
		RegionNote:        r.RegionNote,
		SessionTerminated: r.SessionTerminated,
		TerminationReason: r.TerminationReason,
	}
}

// DetectStickyKeysOutcome runs sticky-keys detection and returns the typed
// outcome. fast selects the short FastBudget settle profile and enforces the
// never-clean invariant.
//
// A host that drops the pre-auth logon session before the careful profile's
// settle completes never shows a post-trigger screen, so a terminated scan is
// retried once on the short profile — which completes inside that window.
// Only from the careful budget: a --fast scan has no shorter profile left.
func DetectStickyKeysOutcome(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *CheckOutcome {
	plugin := &Plugin{}
	budget := CarefulBudget
	if fast {
		budget = FastBudget
	}
	result := plugin.RunStickyKeysCheck(ctx, target, "", connectTimeout, timeout, noVision, budget, fast)
	result = retryStickyKeysOnTermination(fast, result, func() *StickyKeysResult {
		return plugin.RunStickyKeysCheck(ctx, target, "", connectTimeout, timeout, noVision, FastBudget, true)
	})
	return stickyOutcome(result)
}

// DetectUtilmanOutcome runs utilman detection and returns the typed outcome.
// See DetectStickyKeysOutcome for the budget and termination-retry rules.
func DetectUtilmanOutcome(ctx context.Context, target string, connectTimeout, timeout time.Duration, noVision, fast bool) *CheckOutcome {
	plugin := &Plugin{}
	budget := CarefulBudget
	if fast {
		budget = FastBudget
	}
	result := plugin.RunUtilmanCheck(ctx, target, "", connectTimeout, timeout, noVision, budget, fast)
	result = retryUtilmanOnTermination(fast, result, func() *UtilmanResult {
		return plugin.RunUtilmanCheck(ctx, target, "", connectTimeout, timeout, noVision, FastBudget, true)
	})
	return utilmanOutcome(result)
}
