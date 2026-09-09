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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// TestSeverityTag_NoBackdoorIsInformational is the presentation half of the
// mislabeling this API removed. A non-NLA host whose trigger produced the
// normal accessibility dialog has no backdoor, so it must render as [INFO] --
// never as an elevated finding.
func TestSeverityTag_NoBackdoorIsInformational(t *testing.T) {
	assert.Equal(t, "[INFO]", severityTag(logon.VerdictNoBackdoor))
	assert.Equal(t, "[CRITICAL]", severityTag(logon.VerdictBackdoorConfirmed))
	assert.Equal(t, "[HIGH]", severityTag(logon.VerdictBackdoorLikely),
		"a heuristic-only positive is HIGH, not CRITICAL")
}

// TestSeverityTag covers the full table so a new verdict cannot silently
// inherit [INFO] without someone choosing that.
func TestSeverityTag(t *testing.T) {
	for v, want := range map[logon.Verdict]string{
		logon.VerdictBackdoorConfirmed: "[CRITICAL]",
		logon.VerdictBackdoorLikely:    "[HIGH]",
		logon.VerdictNoBackdoor:        "[INFO]",
		logon.VerdictClean:             "[INFO]",
		logon.VerdictNLARequired:       "[INFO]",
		logon.VerdictUnreachable:       "[INFO]",
		logon.VerdictIndeterminate:     "[WARN]",
		logon.VerdictCancelled:         "[WARN]",
		logon.VerdictUnknown:           "[WARN]",
	} {
		assert.Equal(t, want, severityTag(v), "severityTag(%s)", v)
	}
}

// TestIndeterminateMessage checks the operator-facing text. "render did not
// stabilize -- rerun" sends the operator to repeat an identical scan that fails
// identically; a torn-down session needs the short profile instead. Moved here
// from internal/plugins/rdp along with the prose itself.
func TestIndeterminateMessage(t *testing.T) {
	plain := indeterminateMessage("Sticky keys", &logon.Diagnostics{})
	assert.Contains(t, plain, "render did not stabilize")
	assert.NotContains(t, plain, "--fast")

	reason := "session terminated: [Protocol independent error] The disconnection was initiated by the user logging off his or her session on the server"
	withReason := indeterminateMessage("Sticky keys", &logon.Diagnostics{
		SessionTerminated: true, TerminationReason: reason,
	})
	assert.Contains(t, withReason, "server ended the session mid-scan")
	assert.Contains(t, withReason, reason, "the server's own reason is the diagnostic; it must not be dropped")
	assert.Contains(t, withReason, "--fast", "the message must name the actionable next step")

	noReason := indeterminateMessage("Utilman", &logon.Diagnostics{SessionTerminated: true})
	assert.Contains(t, noReason, "server ended the session mid-scan")
	assert.Contains(t, noReason, "--fast")
}

// TestFindingMessage_TerminationBeatsSkipReason covers the seam where a check
// never completed AND the server tore the session down. "could not connect"
// misdirects an operator whose connect worked and whose session was killed
// after, so the teardown must win. Moved here from internal/plugins/rdp.
func TestFindingMessage_TerminationBeatsSkipReason(t *testing.T) {
	const reason = "session terminated: logoff by user"

	msg := findingMessage(&logon.Finding{
		Target: "h:3389", Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictIndeterminate,
		Diagnostics: logon.Diagnostics{
			SkipReason:        "session failed: pump baseline: session error",
			SessionTerminated: true,
			TerminationReason: reason,
		},
	})

	assert.Contains(t, msg, "server ended the session mid-scan")
	assert.Contains(t, msg, reason)
	assert.NotContains(t, msg, "could not connect",
		"a mid-scan teardown is not a failed connect")
}

// TestFindingMessage_PerVerdict pins that each verdict renders text an operator
// can act on, and that the two positives report their confidence.
func TestFindingMessage_PerVerdict(t *testing.T) {
	for _, tc := range []struct {
		verdict  logon.Verdict
		contains []string
	}{
		{logon.VerdictBackdoorConfirmed, []string{"CONFIRMED", "62%"}},
		{logon.VerdictBackdoorLikely, []string{"likely", "62%"}},
		{logon.VerdictNoBackdoor, []string{"Non-NLA", "no backdoor"}},
		{logon.VerdictClean, []string{"clean", "5x Shift"}},
		{logon.VerdictUnknown, []string{"unrecognized verdict"}},
	} {
		msg := findingMessage(&logon.Finding{
			Target: "h:3389", Check: logon.BackdoorStickyKeys,
			Verdict: tc.verdict, Confidence: 0.62,
		})
		for _, want := range tc.contains {
			assert.Contains(t, msg, want, "verdict %s", tc.verdict)
		}
	}
}

// TestFindingMessage_NamesTheTriggerPerCheck pins that a clean reading says
// what it was clean OF -- the two checks send different keystrokes.
func TestFindingMessage_NamesTheTriggerPerCheck(t *testing.T) {
	sticky := findingMessage(&logon.Finding{Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictClean})
	assert.Contains(t, sticky, "5x Shift")
	assert.Contains(t, sticky, "Sticky keys")

	utilman := findingMessage(&logon.Finding{Check: logon.BackdoorUtilman, Verdict: logon.VerdictClean})
	assert.Contains(t, utilman, "Win+U")
	assert.Contains(t, utilman, "Utilman")
}

// TestFindingMessage_AppendsRegionNote pins that the geometry diagnostic still
// reaches the operator. It never changes the verdict, only explains it.
func TestFindingMessage_AppendsRegionNote(t *testing.T) {
	msg := findingMessage(&logon.Finding{
		Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictBackdoorConfirmed,
		Confidence:  0.9,
		Diagnostics: logon.Diagnostics{RegionNote: "console-shaped + dark-region confirmed"},
	})
	assert.Contains(t, msg, "console-shaped + dark-region confirmed")
}

// TestFindingMessage_TerminalStatesCarryTheirReason pins that a host which was
// never scanned says why, rather than rendering as an unexplained INFO line.
func TestFindingMessage_TerminalStatesCarryTheirReason(t *testing.T) {
	nla := findingMessage(&logon.Finding{
		Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictNLARequired,
		Diagnostics: logon.Diagnostics{SkipReason: "NLA/CredSSP enforced; not scannable"},
	})
	assert.Contains(t, nla, "nla_required")
	assert.Contains(t, nla, "NLA/CredSSP enforced")

	unreachable := findingMessage(&logon.Finding{
		Check: logon.BackdoorUtilman, Verdict: logon.VerdictUnreachable,
		Diagnostics: logon.Diagnostics{SkipReason: "no RDP/TCP connection to host:port"},
	})
	assert.Contains(t, unreachable, "unreachable")
	assert.Contains(t, unreachable, "no RDP/TCP connection")
}

// TestOutputScanJSONL_ShapeAndVerdict pins the pipeline contract: the record
// keys on a self-describing verdict, exposes confidence as a number, and has NO
// "success" field -- the field that used to report a host with no backdoor as a
// positive.
func TestOutputScanJSONL_ShapeAndVerdict(t *testing.T) {
	var buf bytes.Buffer
	outputScanJSONL(&buf, []logon.Finding{
		{
			Target: "10.0.0.5:3389", Check: logon.BackdoorStickyKeys,
			Verdict: logon.VerdictBackdoorLikely, Confidence: 0.55, Stabilized: true,
			Diagnostics: logon.Diagnostics{Heuristic: "8% dark delta"},
		},
		{
			Target: "10.0.0.6:3389", Check: logon.BackdoorUtilman,
			Verdict: logon.VerdictNoBackdoor, Confidence: 0.8, Stabilized: true,
		},
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2, "one JSON object per finding")

	var first map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	assert.Equal(t, "rdp", first["protocol"])
	assert.Equal(t, "10.0.0.5:3389", first["target"])
	assert.Equal(t, "stickykeys", first["check"])
	assert.Equal(t, "backdoor_likely", first["verdict"])
	assert.Equal(t, "[HIGH]", first["severity"])
	assert.InDelta(t, 0.55, first["confidence"], 1e-9)
	assert.Equal(t, true, first["positive"])
	assert.Equal(t, false, first["needs_rerun"])
	assert.Equal(t, "8% dark delta", first["heuristic"])
	assert.NotContains(t, first, "success",
		"the overloaded success field is gone; consumers key on verdict")

	var second map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	assert.Equal(t, "utilman", second["check"])
	assert.Equal(t, "no_backdoor", second["verdict"])
	assert.Equal(t, "[INFO]", second["severity"])
	assert.Equal(t, false, second["positive"],
		"a host with no backdoor must never serialize as a positive")
}

// TestOutputScanJSONL_OmitsEmptyDiagnostics keeps the pipeline record readable:
// diagnostics that were never produced must not appear as empty strings.
func TestOutputScanJSONL_OmitsEmptyDiagnostics(t *testing.T) {
	var buf bytes.Buffer
	outputScanJSONL(&buf, []logon.Finding{
		{Target: "h:3389", Check: logon.BackdoorStickyKeys, Verdict: logon.VerdictClean},
	})

	var rec map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec))
	for _, k := range []string{"heuristic", "vision", "region_note", "skip_reason", "termination_reason"} {
		assert.NotContains(t, rec, k, "empty %q must be omitted", k)
	}
}

// TestOutputInteractionJSON pins that an operator-driven interaction serializes
// as its own shape, not as a scan finding.
func TestOutputInteractionJSON(t *testing.T) {
	var buf bytes.Buffer
	outputInteractionJSON(&buf, &logon.InteractionResult{
		Target: "10.0.0.5:3389", Mode: logon.InteractionExec,
		Succeeded: true, Output: "nt authority\\system",
	})

	var rec map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec))
	assert.Equal(t, "exec", rec["mode"])
	assert.Equal(t, true, rec["succeeded"])
	assert.Equal(t, "nt authority\\system", rec["output"])
	assert.NotContains(t, rec, "verdict", "an interaction is not a detection verdict")
}
