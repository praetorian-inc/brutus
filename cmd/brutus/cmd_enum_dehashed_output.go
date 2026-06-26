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

// outputDehashedHuman renders DeHashed breach records as an aligned table. All
// strings are breach-sourced and therefore hostile-controlled, so every field
// is sanitized via sanitizeTerminal and truncated (P0-4). Passwords and hashes
// are never present in the data model, so they cannot appear here (P0-SCOPE).
func outputDehashedHuman(w io.Writer, result *dehashed.DomainResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "DeHashed: "+sanitizeTerminal(result.Domain)))
	_, _ = fmt.Fprintf(w, "  Records found: %d (total: %d)\n", len(result.Records), result.Total)
	if result.Balance > 0 {
		_, _ = fmt.Fprintf(w, "  API credits remaining: %d\n", result.Balance)
	}

	if len(result.Records) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No records found for this domain\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	// Header row.
	_, _ = fmt.Fprintf(w, "\n  %s%-32s %-22s %-22s %-20s %-12s%s\n",
		colorIf(useColor, ColorBold),
		"Email", "Username", "Name", "Database", "Date",
		colorIf(useColor, ColorReset))

	for i := range result.Records {
		r := &result.Records[i]
		_, _ = fmt.Fprintf(w, "  %s%-32s%s %-22s %-22s %-20s %-12s\n",
			colorIf(useColor, ColorGreen),
			truncate(sanitizeTerminal(joinField(r.Email)), 32),
			colorIf(useColor, ColorReset),
			truncate(sanitizeTerminal(joinField(r.Username)), 22),
			truncate(sanitizeTerminal(joinField(r.Name)), 22),
			truncate(sanitizeTerminal(r.Database), 20),
			truncate(sanitizeTerminal(r.ObtainedDate), 12))
	}
	_, _ = fmt.Fprintln(w)
}

// joinField renders a multi-value breach field as a comma-separated string.
func joinField(values []string) string {
	return strings.Join(values, ", ")
}

// outputDehashedJSONL writes one JSON object per record. The record shape
// carries NO password / hashed_password keys (P0-SCOPE). encoding/json escapes
// control characters, so no sanitization is needed.
func outputDehashedJSONL(w io.Writer, result *dehashed.DomainResult) {
	type dehashedJSON struct {
		Type         string   `json:"type"`
		Domain       string   `json:"domain"`
		ID           string   `json:"id,omitempty"`
		Email        []string `json:"email,omitempty"`
		Username     []string `json:"username,omitempty"`
		Name         []string `json:"name,omitempty"`
		IPAddress    []string `json:"ip_address,omitempty"`
		Phone        []string `json:"phone,omitempty"`
		Address      []string `json:"address,omitempty"`
		DOB          []string `json:"dob,omitempty"`
		Database     string   `json:"database,omitempty"`
		ObtainedDate string   `json:"obtained_date,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range result.Records {
		r := &result.Records[i]
		jr := dehashedJSON{
			Type:         "dehashed",
			Domain:       result.Domain,
			ID:           r.ID,
			Email:        r.Email,
			Username:     r.Username,
			Name:         r.Name,
			IPAddress:    r.IPAddress,
			Phone:        r.Phone,
			Address:      r.Address,
			DOB:          r.DOB,
			Database:     r.Database,
			ObtainedDate: r.ObtainedDate,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding dehashed JSON: %v\n", err)
		}
	}
}
