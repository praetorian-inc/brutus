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

import "github.com/praetorian-inc/brutus/internal/plugins/rdp"

// Verdict is the outcome of one logon-screen check.
type Verdict string

const (
	VerdictBackdoorConfirmed Verdict = "backdoor_confirmed"
	VerdictBackdoorLikely    Verdict = "backdoor_likely"
	// VerdictNoBackdoor: the trigger produced the normal accessibility dialog.
	// The detection layer still names this "vulnerable".
	VerdictNoBackdoor    Verdict = "no_backdoor"
	VerdictClean         Verdict = "clean"
	VerdictIndeterminate Verdict = "indeterminate"
	VerdictCanceled      Verdict = "canceled"
	VerdictNLARequired   Verdict = "nla_required"
	VerdictUnreachable   Verdict = "unreachable"
	VerdictUnknown       Verdict = "unknown"
)

func (v Verdict) Positive() bool {
	return v == VerdictBackdoorConfirmed || v == VerdictBackdoorLikely
}

func (v Verdict) Scanned() bool {
	return v.Positive() || v == VerdictNoBackdoor || v == VerdictClean
}

func (v Verdict) NeedsRerun() bool {
	return v == VerdictIndeterminate || v == VerdictCanceled
}

// Diagnostics is the operator-facing detail behind a Verdict.
type Diagnostics struct {
	Heuristic         string
	Vision            string
	RegionNote        string
	SkipReason        string
	SessionTerminated bool
	TerminationReason string
}

// Finding is the outcome of one logon-screen backdoor check against one target.
type Finding struct {
	Target      string
	Check       BackdoorType
	Verdict     Verdict
	Confidence  float64
	Stabilized  bool
	Diagnostics Diagnostics
}

func AnyPositive(findings []Finding) bool {
	for i := range findings {
		if findings[i].Verdict.Positive() {
			return true
		}
	}
	return false
}

func AnyNeedsRerun(findings []Finding) bool {
	for i := range findings {
		if findings[i].Verdict.NeedsRerun() {
			return true
		}
	}
	return false
}

func verdictFromRDP(raw string) Verdict {
	switch raw {
	case "backdoor_confirmed":
		return VerdictBackdoorConfirmed
	case "backdoor_likely":
		return VerdictBackdoorLikely
	case "vulnerable":
		return VerdictNoBackdoor
	case "clean":
		return VerdictClean
	case "indeterminate":
		return VerdictIndeterminate
	default:
		return VerdictUnknown
	}
}

func findingFrom(target string, out *rdp.CheckOutcome) Finding {
	f := Finding{
		Target:     target,
		Check:      out.Check,
		Confidence: out.Confidence,
		Stabilized: out.Stabilized,
		Diagnostics: Diagnostics{
			Heuristic:         out.Heuristic,
			Vision:            out.Vision,
			RegionNote:        out.RegionNote,
			SkipReason:        out.SkipReason,
			SessionTerminated: out.SessionTerminated,
			TerminationReason: out.TerminationReason,
		},
	}

	switch {
	case out.Unreachable:
		f.Verdict = VerdictUnreachable
	case !out.Performed:
		f.Verdict = VerdictIndeterminate
	default:
		f.Verdict = verdictFromRDP(out.Verdict)
	}
	return f
}

func terminalFindings(target string, checks Check, verdict Verdict, skipReason string) []Finding {
	var findings []Finding
	for _, c := range checks.types() {
		findings = append(findings, Finding{
			Target:      target,
			Check:       c,
			Verdict:     verdict,
			Diagnostics: Diagnostics{SkipReason: skipReason},
		})
	}
	return findings
}
