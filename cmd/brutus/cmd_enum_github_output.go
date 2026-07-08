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

	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

// outputGithubEnumResultLine prints ONE GitHub enumeration result row. EXISTS
// rows show the email and an "[+] EXISTS" label, plus the revealed username (if
// any) as " (<username>)". Not-found rows render as "[ ] not found". The
// server-/user-derived email and username are sanitized via sanitizeTerminal
// (P0-4) before rendering. Callers decide which results to print.
func outputGithubEnumResultLine(w io.Writer, r githubenum.Result, useColor bool) {
	email := truncate(sanitizeTerminal(r.Email), 40)

	if !r.Exists {
		_, _ = fmt.Fprintf(w, "  %-40s %s[ ] not found%s\n",
			email, colorIf(useColor, ColorDim), colorIf(useColor, ColorReset))
		return
	}

	note := ""
	if r.Username != "" {
		note = " (" + sanitizeTerminal(r.Username) + ")"
	}

	_, _ = fmt.Fprintf(w, "  %-40s %s%s EXISTS%s%s\n",
		email,
		colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
		dim(useColor, note))
}

// outputGithubEnumUsernames prints the resolved username:email mappings for
// results that have a revealed username, under a small heading.
func outputGithubEnumUsernames(w io.Writer, results []githubenum.Result, useColor bool) {
	var anyMatch bool
	for i := range results {
		if results[i].Username != "" {
			anyMatch = true
			break
		}
	}
	if !anyMatch {
		return
	}

	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Revealed Usernames"))
	for i := range results {
		if results[i].Username == "" {
			continue
		}
		_, _ = fmt.Fprintf(w, "    %s%s%s:%s\n",
			colorIf(useColor, ColorCyan), sanitizeTerminal(results[i].Username), colorIf(useColor, ColorReset),
			" "+sanitizeTerminal(results[i].Email))
	}
}

// outputGithubEnumSummary prints the counts-by-status summary block: found /
// revealed / not found / errors / total.
func outputGithubEnumSummary(w io.Writer, results []githubenum.Result, useColor bool) {
	var foundCount, revealedCount, notFoundCount, errorCount int
	for i := range results {
		switch {
		case results[i].Error != nil:
			errorCount++
		case results[i].Exists:
			foundCount++
			if results[i].Username != "" {
				revealedCount++
			}
		default:
			notFoundCount++
		}
	}

	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Summary"))
	if foundCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), foundCount)
	}
	if revealedCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sUsernames:%s  %d\n", colorIf(useColor, ColorCyan), colorIf(useColor, ColorReset), revealedCount)
	}
	if notFoundCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sNot found:%s  %d\n", colorIf(useColor, ColorDim), colorIf(useColor, ColorReset), notFoundCount)
	}
	if errorCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sErrors:%s     %d\n", colorIf(useColor, ColorRed), colorIf(useColor, ColorReset), errorCount)
	}
	_, _ = fmt.Fprintf(w, "    %sTotal:%s      %d\n", colorIf(useColor, ColorCyan), colorIf(useColor, ColorReset), len(results))
	_, _ = fmt.Fprintln(w)
}

// outputGithubEnumJSONL writes one JSON object per result. encoding/json escapes
// control characters, so no sanitization is needed.
func outputGithubEnumJSONL(w io.Writer, results []githubenum.Result) {
	type githubEnumJSON struct {
		Type     string `json:"type"`
		Email    string `json:"email"`
		Exists   bool   `json:"exists"`
		Username string `json:"username,omitempty"`
		Error    string `json:"error,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := githubEnumJSON{
			Type:     "github_account",
			Email:    r.Email,
			Exists:   r.Exists,
			Username: r.Username,
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding github enum JSON: %v\n", err)
		}
	}
}
