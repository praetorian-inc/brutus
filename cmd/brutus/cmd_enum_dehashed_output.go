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
	"strings"

	"github.com/praetorian-inc/brutus/pkg/enum/dehashed"
)

// ---------------------------------------------------------------------------
// DeHashed output functions
// ---------------------------------------------------------------------------

// outputDehashedHuman renders refined DeHashed contacts as an aligned table.
// All strings are breach-sourced and therefore hostile-controlled, so every
// field is sanitized via sanitizeTerminal and truncated (P0-4) — including the
// passwords, which are attacker-controlled strings. When showCredentials is
// true, a Password(s) column is rendered; when false the column is omitted
// entirely. rawFetched is the number of raw breach records fetched; total is
// the raw API total available.
func outputDehashedHuman(w io.Writer, domain string, rawFetched, total, balance int, entries []dehashed.Entry, useColor, showCredentials bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "DeHashed: "+sanitizeTerminal(domain)))
	_, _ = fmt.Fprintf(w, "  %d records → %d unique contacts (total available: %d)\n",
		rawFetched, len(entries), total)
	if balance > 0 {
		_, _ = fmt.Fprintf(w, "  API credits remaining: %d\n", balance)
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No matching records for this domain\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	// Header row. The Password(s) column is only present with showCredentials.
	if showCredentials {
		_, _ = fmt.Fprintf(w, "\n  %s%-32s %-22s %-22s %-18s %-20s %-24s%s\n",
			colorIf(useColor, ColorBold),
			"Email", "Name", "Username", "Phone", "Sources", "Password(s)",
			colorIf(useColor, ColorReset))
	} else {
		_, _ = fmt.Fprintf(w, "\n  %s%-32s %-22s %-22s %-18s %-20s%s\n",
			colorIf(useColor, ColorBold),
			"Email", "Name", "Username", "Phone", "Sources",
			colorIf(useColor, ColorReset))
	}

	for i := range entries {
		e := &entries[i]
		if showCredentials {
			_, _ = fmt.Fprintf(w, "  %s%-32s%s %-22s %-22s %-18s %-20s %-24s\n",
				colorIf(useColor, ColorGreen),
				truncate(sanitizeTerminal(e.Email), 32),
				colorIf(useColor, ColorReset),
				truncate(sanitizeTerminal(joinField(e.Names)), 22),
				truncate(sanitizeTerminal(joinField(e.Usernames)), 22),
				truncate(sanitizeTerminal(joinField(e.Phones)), 18),
				truncate(sanitizeTerminal(joinSources(e.Databases)), 20),
				truncate(sanitizeTerminal(joinField(e.Passwords)), 24))
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s%-32s%s %-22s %-22s %-18s %-20s\n",
			colorIf(useColor, ColorGreen),
			truncate(sanitizeTerminal(e.Email), 32),
			colorIf(useColor, ColorReset),
			truncate(sanitizeTerminal(joinField(e.Names)), 22),
			truncate(sanitizeTerminal(joinField(e.Usernames)), 22),
			truncate(sanitizeTerminal(joinField(e.Phones)), 18),
			truncate(sanitizeTerminal(joinSources(e.Databases)), 20))
	}
	_, _ = fmt.Fprintln(w)
}

// joinField renders a multi-value breach field as a comma-separated string.
func joinField(values []string) string {
	return strings.Join(values, ", ")
}

// joinSources renders the distinct source databases, appending "(+N)" when more
// than two contributed so the column stays scannable.
func joinSources(databases []string) string {
	if len(databases) <= 2 {
		return strings.Join(databases, ", ")
	}
	return strings.Join(databases[:2], ", ") + fmt.Sprintf(" (+%d)", len(databases)-2)
}

// outputDehashedJSONL writes one JSON object per refined entry. When
// showCredentials is true, each object includes the breach-exposed plaintext
// "passwords" (omitempty); when false the key is omitted entirely. The
// hashed_password field is never present (P0-SCOPE). encoding/json escapes
// control characters, so no sanitization is needed.
func outputDehashedJSONL(w io.Writer, entries []dehashed.Entry, showCredentials bool) {
	type dehashedJSON struct {
		Type      string   `json:"type"`
		Email     string   `json:"email"`
		Names     []string `json:"names,omitempty"`
		Usernames []string `json:"usernames,omitempty"`
		Phones    []string `json:"phones,omitempty"`
		Passwords []string `json:"passwords,omitempty"`
		Databases []string `json:"databases"`
		Count     int      `json:"count"`
	}

	enc := json.NewEncoder(w)
	for i := range entries {
		e := &entries[i]
		jr := dehashedJSON{
			Type:      "dehashed",
			Email:     e.Email,
			Names:     e.Names,
			Usernames: e.Usernames,
			Phones:    e.Phones,
			Databases: e.Databases,
			Count:     e.Count,
		}
		if showCredentials {
			jr.Passwords = e.Passwords
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding dehashed JSON: %v\n", err)
		}
	}
}
