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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
)

// TestVerdictFromRDP_VulnerableIsNotAFinding is the regression pin for the
// defect this typed API exists to make unrepresentable.
//
// The detection layer's verdict string "vulnerable" means "the trigger fired
// and produced the NORMAL Windows accessibility dialog on a non-NLA host" --
// i.e. no backdoor. The old []brutus.Result API set Success=true for it,
// because Success meant "the trigger elicited a response", and DetectBackdoors
// OR-ed Success across checks into its hasSuccess return. Any consumer reading
// Success as "a backdoor is present" therefore reported a critical finding on a
// host that has none.
//
// The verdict must translate to a name that cannot be misread, and must not be
// Positive().
func TestVerdictFromRDP_VulnerableIsNotAFinding(t *testing.T) {
	v := verdictFromRDP("vulnerable")

	assert.Equal(t, VerdictNoBackdoor, v,
		"the vulnerable verdict means no backdoor was found")
	assert.False(t, v.Positive(),
		"a host with no backdoor must never be reported as a positive")
	assert.True(t, v.Scanned(),
		"the check ran and reached a real reading, so it is not a rerun candidate")
	assert.False(t, v.NeedsRerun(),
		"a real observation must never be discarded by a rerun")
}

// TestVerdictFromRDP covers the whole translation table. Unknown strings must
// fail closed: never clean (a false negative) and never indeterminate (which
// would make every host retry the moment upstream adds a verdict string).
func TestVerdictFromRDP(t *testing.T) {
	for raw, want := range map[string]Verdict{
		"backdoor_confirmed": VerdictBackdoorConfirmed,
		"backdoor_likely":    VerdictBackdoorLikely,
		"vulnerable":         VerdictNoBackdoor,
		"clean":              VerdictClean,
		"indeterminate":      VerdictIndeterminate,
		"":                   VerdictUnknown,
		"something_new":      VerdictUnknown,
	} {
		assert.Equal(t, want, verdictFromRDP(raw), "verdict %q", raw)
	}

	assert.False(t, VerdictUnknown.Positive(), "an unrecognized verdict is not a finding")
	assert.False(t, VerdictUnknown.Scanned(), "an unrecognized verdict is not a reading")
	assert.False(t, VerdictUnknown.NeedsRerun(), "an unrecognized verdict must not trigger retries")
}

// TestVerdictPredicates pins the three predicates across every verdict, so the
// classification of a new verdict is a deliberate choice rather than whatever
// the default branch happens to do.
func TestVerdictPredicates(t *testing.T) {
	for _, tc := range []struct {
		v          Verdict
		positive   bool
		scanned    bool
		needsRerun bool
	}{
		{VerdictBackdoorConfirmed, true, true, false},
		{VerdictBackdoorLikely, true, true, false},
		{VerdictNoBackdoor, false, true, false},
		{VerdictClean, false, true, false},
		{VerdictIndeterminate, false, false, true},
		{VerdictCancelled, false, false, true},
		{VerdictNLARequired, false, false, false},
		{VerdictUnreachable, false, false, false},
		{VerdictUnknown, false, false, false},
	} {
		assert.Equal(t, tc.positive, tc.v.Positive(), "%s.Positive()", tc.v)
		assert.Equal(t, tc.scanned, tc.v.Scanned(), "%s.Scanned()", tc.v)
		assert.Equal(t, tc.needsRerun, tc.v.NeedsRerun(), "%s.NeedsRerun()", tc.v)
	}
}

// TestFindingFrom_UnreachableBeatsNotPerformed pins the precedence that keeps
// unreachable hosts out of the retry loop. A failed dial is terminal; every
// other failure to run produced no reading and must be rerun. Neither is ever
// clean -- the cardinal false-negative rule.
func TestFindingFrom_UnreachableBeatsNotPerformed(t *testing.T) {
	unreachable := findingFrom("h:3389", &rdp.CheckOutcome{
		Check: rdp.BackdoorStickyKeys, Performed: false, Unreachable: true,
		SkipReason: "connection failed: i/o timeout",
	})
	assert.Equal(t, VerdictUnreachable, unreachable.Verdict)
	assert.False(t, unreachable.Verdict.NeedsRerun(), "a dead host must not be retried")
	assert.False(t, unreachable.Verdict.Scanned())
	assert.Equal(t, "connection failed: i/o timeout", unreachable.Diagnostics.SkipReason)

	wasmFailure := findingFrom("h:3389", &rdp.CheckOutcome{
		Check: rdp.BackdoorUtilman, Performed: false, Unreachable: false,
		SkipReason: "wasm instance: boom",
	})
	assert.Equal(t, VerdictIndeterminate, wasmFailure.Verdict)
	assert.True(t, wasmFailure.Verdict.NeedsRerun(), "a check that never ran is worth rerunning")
	assert.NotEqual(t, VerdictClean, wasmFailure.Verdict, "a failure to run is never clean")
}

// TestFindingFrom_CarriesVerdictAndDiagnostics pins that the conversion is
// lossless for everything a consumer renders or triages on. Confidence in
// particular used to survive only as a percentage inside banner prose.
func TestFindingFrom_CarriesVerdictAndDiagnostics(t *testing.T) {
	f := findingFrom("10.0.0.5:3389", &rdp.CheckOutcome{
		Check:             rdp.BackdoorStickyKeys,
		Performed:         true,
		Stabilized:        true,
		Verdict:           "backdoor_likely",
		Confidence:        0.55,
		Heuristic:         "8% dark delta",
		RegionNote:        "console-shaped",
		SessionTerminated: true,
		TerminationReason: "logoff by user",
	})

	assert.Equal(t, "10.0.0.5:3389", f.Target)
	assert.Equal(t, BackdoorStickyKeys, f.Check)
	assert.Equal(t, VerdictBackdoorLikely, f.Verdict)
	assert.InDelta(t, 0.55, f.Confidence, 1e-9,
		"confidence must reach the consumer as a number, not as text in a banner")
	assert.True(t, f.Stabilized)
	assert.Equal(t, "8% dark delta", f.Diagnostics.Heuristic)
	assert.Equal(t, "console-shaped", f.Diagnostics.RegionNote)
	assert.True(t, f.Diagnostics.SessionTerminated)
	assert.Equal(t, "logoff by user", f.Diagnostics.TerminationReason)
}

// TestTerminalFindings_RespectsSelector pins that a host which was never
// scanned still reports exactly the checks the scan would have run.
func TestTerminalFindings_RespectsSelector(t *testing.T) {
	for _, tc := range []struct {
		checks Check
		want   []BackdoorType
	}{
		{CheckBoth, []BackdoorType{BackdoorStickyKeys, BackdoorUtilman}},
		{CheckStickyKeys, []BackdoorType{BackdoorStickyKeys}},
		{CheckUtilman, []BackdoorType{BackdoorUtilman}},
	} {
		got := terminalFindings("h:3389", tc.checks, VerdictNLARequired, "NLA enforced")
		require.Len(t, got, len(tc.want))
		for i := range tc.want {
			assert.Equal(t, tc.want[i], got[i].Check)
			assert.Equal(t, VerdictNLARequired, got[i].Verdict)
			assert.Equal(t, "NLA enforced", got[i].Diagnostics.SkipReason)
			assert.Equal(t, "h:3389", got[i].Target)
		}
	}
}

// TestAnyPositive_IgnoresNonFindings guards the aggregate helper against the
// same conflation the old hasSuccess bool had: only a real backdoor counts.
func TestAnyPositive_IgnoresNonFindings(t *testing.T) {
	assert.False(t, AnyPositive(nil))
	assert.False(t, AnyPositive([]Finding{
		{Verdict: VerdictNoBackdoor},
		{Verdict: VerdictClean},
		{Verdict: VerdictNLARequired},
		{Verdict: VerdictUnreachable},
		{Verdict: VerdictIndeterminate},
		{Verdict: VerdictUnknown},
	}), "none of these observed a backdoor")

	assert.True(t, AnyPositive([]Finding{
		{Verdict: VerdictClean},
		{Verdict: VerdictBackdoorLikely},
	}))
}

// TestAnyNeedsRerun covers the retry trigger, including that the terminal
// not-scannable states are excluded from it.
func TestAnyNeedsRerun(t *testing.T) {
	assert.False(t, AnyNeedsRerun(nil))
	assert.False(t, AnyNeedsRerun([]Finding{
		{Verdict: VerdictNLARequired},
		{Verdict: VerdictUnreachable},
	}), "terminal states cannot be improved by a rerun")

	assert.True(t, AnyNeedsRerun([]Finding{
		{Verdict: VerdictClean},
		{Verdict: VerdictIndeterminate},
	}))
	assert.True(t, AnyNeedsRerun([]Finding{{Verdict: VerdictCancelled}}))
}
