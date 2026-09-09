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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// Presentation for the logon-screen detection path.
//
// All operator-facing prose for a logon scan is rendered HERE, from the typed
// logon.Finding. It used to be rendered inside the detection library and
// shipped out as a banner string, which meant every consumer — this CLI
// included — parsed English back into a severity. The library now returns a
// verdict, and rendering it is this layer's job alone.

// severityTag maps a verdict to the operator-facing severity label.
//
// Only the two positive verdicts are elevated. VerdictNoBackdoor is INFO: the
// check ran and found no backdoor, which is not a finding no matter that the
// trigger produced a visible response.
func severityTag(v logon.Verdict) string {
	switch v {
	case logon.VerdictBackdoorConfirmed:
		return "[CRITICAL]"
	case logon.VerdictBackdoorLikely:
		return "[HIGH]"
	case logon.VerdictIndeterminate, logon.VerdictCancelled, logon.VerdictUnknown:
		return "[WARN]"
	default:
		return "[INFO]"
	}
}

// checkLabel names the check in human output.
func checkLabel(c logon.BackdoorType) string {
	if c == logon.BackdoorUtilman {
		return "Utilman Scan"
	}
	return "Sticky Keys Scan"
}

// triggerLabel names the keystroke a check sends, so a clean reading says what
// it was clean of.
func triggerLabel(c logon.BackdoorType) string {
	if c == logon.BackdoorUtilman {
		return "Win+U"
	}
	return "5x Shift"
}

// checkNoun names the check inside a sentence.
func checkNoun(c logon.BackdoorType) string {
	if c == logon.BackdoorUtilman {
		return "Utilman"
	}
	return "Sticky keys"
}

// findingMessage renders the operator-facing explanation of a verdict.
func findingMessage(f *logon.Finding) string {
	noun := checkNoun(f.Check)
	d := &f.Diagnostics

	var msg string
	switch f.Verdict {
	case logon.VerdictBackdoorConfirmed:
		msg = fmt.Sprintf("%s backdoor CONFIRMED (confidence: %.0f%%)", noun, f.Confidence*100)
	case logon.VerdictBackdoorLikely:
		msg = fmt.Sprintf("%s backdoor likely (confidence: %.0f%%)", noun, f.Confidence*100)
	case logon.VerdictNoBackdoor:
		msg = fmt.Sprintf("Non-NLA target, %s triggers normally (no backdoor)", noun)
	case logon.VerdictClean:
		msg = fmt.Sprintf("%s check: clean (no response to %s)", noun, triggerLabel(f.Check))
	case logon.VerdictIndeterminate:
		msg = indeterminateMessage(noun, d)
	case logon.VerdictCancelled:
		msg = fmt.Sprintf("%s check CANCELLED (%s)", noun, d.SkipReason)
	case logon.VerdictNLARequired:
		msg = fmt.Sprintf("nla_required (%s)", d.SkipReason)
	case logon.VerdictUnreachable:
		msg = fmt.Sprintf("unreachable (%s)", d.SkipReason)
	default:
		msg = fmt.Sprintf("%s check returned an unrecognized verdict", noun)
	}

	// Geometry diagnostic: never affects the verdict, only explains it.
	if d.RegionNote != "" {
		msg += fmt.Sprintf(" (%s)", d.RegionNote)
	}
	return msg
}

// indeterminateMessage explains a check that produced no trustworthy render.
//
// A server that ended the session mid-scan is called out by name, with the
// reason it gave, because "render did not stabilize" sends the operator to
// rerun an identical scan that will fail identically — the actionable step is
// the short settle profile, which completes inside the window such a host
// allows before it drops the pre-auth session.
func indeterminateMessage(noun string, d *logon.Diagnostics) string {
	switch {
	case d.SessionTerminated && d.TerminationReason != "":
		return fmt.Sprintf("%s check INDETERMINATE (server ended the session mid-scan: %s — retry with --fast)", noun, d.TerminationReason)
	case d.SessionTerminated:
		return fmt.Sprintf("%s check INDETERMINATE (server ended the session mid-scan — retry with --fast)", noun)
	case d.SkipReason != "":
		return fmt.Sprintf("%s check INDETERMINATE (%s)", noun, d.SkipReason)
	default:
		return fmt.Sprintf("%s check INDETERMINATE (render did not stabilize — rerun)", noun)
	}
}

// outputScanHuman writes logon scan findings in human-readable format.
func outputScanHuman(findings []logon.Finding, useColor bool) {
	for i := range findings {
		f := &findings[i]
		tag := severityTag(f.Verdict)
		msg := fmt.Sprintf("%s %s", tag, findingMessage(f))

		color, symbol := ColorCyan, SymbolInfo
		switch tag {
		case "[CRITICAL]":
			color, symbol = ColorRed, SymbolError
		case "[HIGH]", "[WARN]":
			color, symbol = ColorYellow, SymbolWarning
		}

		if useColor {
			fmt.Printf("%s%s %s: %s%s  %s\n", color, symbol, checkLabel(f.Check), f.Target, ColorReset, msg)
		} else {
			fmt.Printf("%s: %s  %s\n", checkLabel(f.Check), f.Target, msg)
		}
	}
}

// scanRecord is the JSONL shape for one logon scan finding.
//
// verdict is the field to key on: it is total and self-describing. There is
// deliberately no "success" field — the old one conflated "a backdoor is
// present" with "the trigger produced a response", and reported a host with no
// backdoor as a positive.
type scanRecord struct {
	Protocol   string  `json:"protocol"`
	Target     string  `json:"target"`
	Check      string  `json:"check"`
	Verdict    string  `json:"verdict"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Message    string  `json:"message"`
	Positive   bool    `json:"positive"`
	NeedsRerun bool    `json:"needs_rerun"`
	Stabilized bool    `json:"stabilized"`

	Heuristic         string `json:"heuristic,omitempty"`
	Vision            string `json:"vision,omitempty"`
	RegionNote        string `json:"region_note,omitempty"`
	SkipReason        string `json:"skip_reason,omitempty"`
	SessionTerminated bool   `json:"session_terminated,omitempty"`
	TerminationReason string `json:"termination_reason,omitempty"`
}

// outputScanJSONL writes logon scan findings as JSONL for pipeline consumption.
func outputScanJSONL(w io.Writer, findings []logon.Finding) {
	enc := json.NewEncoder(w)
	for i := range findings {
		f := &findings[i]
		rec := scanRecord{
			Protocol:          "rdp",
			Target:            f.Target,
			Check:             string(f.Check),
			Verdict:           string(f.Verdict),
			Severity:          severityTag(f.Verdict),
			Confidence:        f.Confidence,
			Message:           findingMessage(f),
			Positive:          f.Verdict.Positive(),
			NeedsRerun:        f.Verdict.NeedsRerun(),
			Stabilized:        f.Stabilized,
			Heuristic:         f.Diagnostics.Heuristic,
			Vision:            f.Diagnostics.Vision,
			RegionNote:        f.Diagnostics.RegionNote,
			SkipReason:        f.Diagnostics.SkipReason,
			SessionTerminated: f.Diagnostics.SessionTerminated,
			TerminationReason: f.Diagnostics.TerminationReason,
		}
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding scan JSON: %v\n", err)
		}
	}
}

// interactionRecord is the JSONL shape for an operator-driven interaction.
type interactionRecord struct {
	Protocol       string `json:"protocol"`
	Target         string `json:"target"`
	Mode           string `json:"mode"`
	Succeeded      bool   `json:"succeeded"`
	Output         string `json:"output,omitempty"`
	ScreenshotPath string `json:"screenshot_path,omitempty"`
	Error          string `json:"error,omitempty"`
}

// outputInteractionHuman writes an exec/web-terminal outcome in human format.
func outputInteractionHuman(r *logon.InteractionResult, useColor bool) {
	var msg string
	switch {
	case r.Err != nil:
		msg = fmt.Sprintf("[WARN] %s failed: %v", r.Mode, r.Err)
	case r.Mode == logon.InteractionWebTerminal:
		msg = "[INFO] Web terminal session ended"
	case r.Output != "":
		msg = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, output:\n%s", r.Succeeded, r.Output)
	default:
		msg = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, screenshot=%s", r.Succeeded, r.ScreenshotPath)
	}

	if useColor {
		color, symbol := ColorCyan, SymbolInfo
		if r.Err != nil || !r.Succeeded {
			color, symbol = ColorYellow, SymbolWarning
		}
		fmt.Printf("%s%s %s: %s%s  %s\n", color, symbol, r.Mode, r.Target, ColorReset, msg)
		return
	}
	fmt.Printf("%s: %s  %s\n", r.Mode, r.Target, msg)
}

// outputInteractionJSON writes an exec/web-terminal outcome as one JSON line.
func outputInteractionJSON(w io.Writer, r *logon.InteractionResult) {
	rec := interactionRecord{
		Protocol:       "rdp",
		Target:         r.Target,
		Mode:           string(r.Mode),
		Succeeded:      r.Succeeded,
		Output:         r.Output,
		ScreenshotPath: r.ScreenshotPath,
	}
	if r.Err != nil {
		rec.Error = r.Err.Error()
	}
	if err := json.NewEncoder(w).Encode(rec); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding interaction JSON: %v\n", err)
	}
}
