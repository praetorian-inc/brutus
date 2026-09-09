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

// Verdict is the outcome of one logon-screen check. It is total: every code
// path that produces a Finding sets exactly one of these, including the states
// that mean "this host was never scanned". Callers switch on it rather than
// reading a bool or matching banner prose.
type Verdict string

const (
	// VerdictBackdoorConfirmed: the trigger opened a console-shaped dark window.
	VerdictBackdoorConfirmed Verdict = "backdoor_confirmed"
	// VerdictBackdoorLikely: a dark window appeared but was not corroborated.
	// Reportable, but weaker than confirmed — it is the only positive the
	// heuristic-only path (no Vision) can reach.
	VerdictBackdoorLikely Verdict = "backdoor_likely"
	// VerdictNoBackdoor: the trigger fired and produced the NORMAL Windows
	// accessibility dialog on a non-NLA host. The check worked and found
	// nothing. Named for what it means: the legacy rdp verdict string for this
	// state is "vulnerable", which reads as a finding and is not one.
	VerdictNoBackdoor Verdict = "no_backdoor"
	// VerdictClean: the trigger produced no response at all.
	VerdictClean Verdict = "clean"
	// VerdictIndeterminate: no verdict could be reached (render never
	// stabilized, connect/wasm failure). Eligible for rerun.
	VerdictIndeterminate Verdict = "indeterminate"
	// VerdictCanceled: the scan was canceled before it started. Never ran, so
	// it is not clean.
	VerdictCanceled Verdict = "canceled"
	// VerdictNLARequired: NLA/CredSSP is enforced, so the logon screen is not
	// reachable pre-auth. Terminal — not scannable, not a rerun candidate.
	VerdictNLARequired Verdict = "nla_required"
	// VerdictUnreachable: no TCP/RDP connection to the host. Terminal.
	VerdictUnreachable Verdict = "unreachable"
	// VerdictUnknown: the detection layer returned a verdict this package does
	// not recognize. Fail-closed — never positive, never clean, and (unlike
	// indeterminate) not retried, so a new upstream verdict string cannot
	// silently multiply every scan's cost.
	VerdictUnknown Verdict = "unknown"
)

// Positive reports whether a backdoor was actually observed.
//
// This is the distinction the old []brutus.Result API could not express:
// brutus.Result.Success was set for VerdictNoBackdoor too, because "the trigger
// elicited a response" and "a backdoor is present" were the same bool. Only
// these two verdicts are findings.
func (v Verdict) Positive() bool {
	return v == VerdictBackdoorConfirmed || v == VerdictBackdoorLikely
}

// Scanned reports whether the check ran and reached a real reading about the
// host. False for the terminal not-scannable states and for a rerun candidate.
func (v Verdict) Scanned() bool {
	return v.Positive() || v == VerdictNoBackdoor || v == VerdictClean
}

// NeedsRerun reports whether the host produced no verdict and is worth
// scanning again. Terminal states (nla_required, unreachable) are excluded:
// rerunning them cannot change the answer.
func (v Verdict) NeedsRerun() bool {
	return v == VerdictIndeterminate || v == VerdictCanceled
}

// Diagnostics carries the operator-facing detail behind a Verdict. It explains
// a verdict; it never determines one.
type Diagnostics struct {
	// Heuristic describes the pixel-delta reading.
	Heuristic string
	// Vision describes the Vision API reading, empty when Vision was disabled.
	Vision string
	// RegionNote records what the geometry classifier saw. Never changes the
	// verdict.
	RegionNote string
	// SkipReason explains a check that did not run (connect/wasm failure).
	SkipReason string
	// SessionTerminated records that the server tore down the RDP session
	// mid-scan, and TerminationReason is the reason it gave.
	SessionTerminated bool
	TerminationReason string
}

// Finding is the outcome of one logon-screen backdoor check against one target.
//
// It is deliberately not brutus.Result: that type describes a credential
// attempt (Username, Password, Key, LLMSuggested) and carries its verdict as
// English prose in Banner, which forced every consumer to parse text back out.
// Logon detection tests no credentials, so it reports its own shape.
type Finding struct {
	// Target is the host:port scanned.
	Target string
	// Check is which accessibility binary was triggered.
	Check BackdoorType
	// Verdict is the outcome. Always set.
	Verdict Verdict
	// Confidence is the detector's 0.0-1.0 confidence in Verdict. Meaningful
	// only when Verdict.Scanned().
	Confidence float64
	// Stabilized records whether both frame pumps settled. A clean reading on
	// an unstabilized render is not trustworthy, which is why the detection
	// layer already downgrades it before the verdict reaches here.
	Stabilized bool
	// Diagnostics is the operator-facing detail behind Verdict.
	Diagnostics Diagnostics
}

// AnyPositive reports whether any finding observed a backdoor. It replaces the
// bool that DetectBackdoors used to return alongside its results.
func AnyPositive(findings []Finding) bool {
	for i := range findings {
		if findings[i].Verdict.Positive() {
			return true
		}
	}
	return false
}

// AnyNeedsRerun reports whether any finding failed to reach a verdict.
func AnyNeedsRerun(findings []Finding) bool {
	for i := range findings {
		if findings[i].Verdict.NeedsRerun() {
			return true
		}
	}
	return false
}

// verdictFromRDP translates a raw detection verdict into a Verdict. Unknown
// strings map to VerdictUnknown rather than to clean or indeterminate: the
// former would be a false negative, the latter would silently retry every host
// on the next upstream verdict string.
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

// findingFrom converts a detection-layer outcome into a Finding.
//
// The not-performed cases are ordered deliberately: a failed TCP dial is
// terminal-unreachable, while every other failure to run (wasm init, wasm
// instance, connector, session) produced no reading and must read as a rerun
// candidate. Neither is ever clean — that is the cardinal false-negative rule.
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

// terminalFindings builds the finding set for a host that was never scanned,
// one per check the selector asked for. Used for the pre-scan terminal states
// (NLA enforced, unreachable, canceled) which are decided before any check
// runs and therefore have no detection outcome to convert.
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
