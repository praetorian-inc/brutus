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

// CheckOutcome is the typed outcome of one logon-screen check.
type CheckOutcome struct {
	Check             BackdoorType
	Performed         bool
	Stabilized        bool
	Unreachable       bool
	SkipReason        string
	Verdict           string
	Confidence        float64
	Heuristic         string
	Vision            string
	RegionNote        string
	SessionTerminated bool
	TerminationReason string
	BaselinePNG       []byte
	ResponsePNG       []byte
}

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
		BaselinePNG:       r.BaselinePNG,
		ResponsePNG:       r.ResponsePNG,
	}
}

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
		BaselinePNG:       r.BaselinePNG,
		ResponsePNG:       r.ResponsePNG,
	}
}

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
	result = retryStickyKeysOnUnstable(fast, result, func() *StickyKeysResult {
		return plugin.RunStickyKeysCheck(ctx, target, "", connectTimeout, patientTimeout(timeout), noVision, PatientBudget, false)
	})
	return stickyOutcome(result)
}

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
	result = retryUtilmanOnUnstable(fast, result, func() *UtilmanResult {
		return plugin.RunUtilmanCheck(ctx, target, "", connectTimeout, patientTimeout(timeout), noVision, PatientBudget, false)
	})
	return utilmanOutcome(result)
}

// patientTimeout widens a per-phase settle deadline for the single more-patient retry of
// a non-stabilized scan. Doubling gives a slow-painting logon screen room to reach the
// wider PatientBudget quiet window; it is bounded so an already-generous --scan-timeout
// cannot balloon a stuck host's cost without limit.
func patientTimeout(d time.Duration) time.Duration {
	const maxPatient = 45 * time.Second
	patient := d * 2
	if patient > maxPatient {
		return maxPatient
	}
	return patient
}
