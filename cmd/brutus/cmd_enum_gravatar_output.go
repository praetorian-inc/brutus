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

	"github.com/praetorian-inc/brutus/pkg/enum/gravatar"
)

// ---------------------------------------------------------------------------
// Gravatar account enumeration output functions
// ---------------------------------------------------------------------------

// outputGravatarEnumResultLine prints ONE Gravatar enumeration result row.
// EXISTS rows show the email and an "[+] EXISTS" label; not-found rows render as
// "[ ] not found". Callers decide which results to print (e.g. EXISTS only,
// unless verbose); this helper renders whatever it is given.
func outputGravatarEnumResultLine(w io.Writer, r gravatar.Result, useColor bool) {
	email := truncate(sanitizeTerminal(r.Email), 40)

	if !r.Exists {
		_, _ = fmt.Fprintf(w, "  %-40s %s[ ] not found%s\n",
			email, colorIf(useColor, ColorDim), colorIf(useColor, ColorReset))
		return
	}

	_, _ = fmt.Fprintf(w, "  %-40s %s%s EXISTS%s\n",
		email,
		colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset))
}

// outputGravatarEnumSummary prints the counts-by-status summary block for a set
// of Gravatar enumeration results: found / not found / errors / total.
func outputGravatarEnumSummary(w io.Writer, results []gravatar.Result, useColor bool) {
	var foundCount, notFoundCount, errorCount int
	for i := range results {
		switch {
		case results[i].Error != nil:
			errorCount++
		case results[i].Exists:
			foundCount++
		default:
			notFoundCount++
		}
	}

	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Summary"))
	if foundCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), foundCount)
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

// gravatarEnumJSON is the JSONL row shape for a Gravatar enumeration result. The
// avatar URL is derived from the hash for convenience.
type gravatarEnumJSON struct {
	Email     string `json:"email"`
	Hash      string `json:"hash"`
	Exists    bool   `json:"exists"`
	AvatarURL string `json:"avatar_url"`
	Error     string `json:"error,omitempty"`
}

// encodeGravatarEnumResult maps a gravatar.Result to its JSONL row.
func encodeGravatarEnumResult(r gravatar.Result) gravatarEnumJSON {
	jr := gravatarEnumJSON{
		Email:     r.Email,
		Hash:      r.Hash,
		Exists:    r.Exists,
		AvatarURL: fmt.Sprintf("https://www.gravatar.com/avatar/%s", r.Hash),
	}
	if r.Error != nil {
		jr.Error = r.Error.Error()
	}
	return jr
}

// outputGravatarEnumJSONL writes one JSON object per result. encoding/json
// escapes control characters, so no sanitization is needed.
func outputGravatarEnumJSONL(w io.Writer, results []gravatar.Result) {
	enc := json.NewEncoder(w)
	for i := range results {
		if err := enc.Encode(encodeGravatarEnumResult(results[i])); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding gravatar enum JSON: %v\n", err)
		}
	}
}
