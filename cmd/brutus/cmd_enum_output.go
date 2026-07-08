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
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/google"
	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
	m365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// outputDNSReconHuman displays DNS TXT recon results in human-readable format.
// When teamsAvailable is true (the org is a Microsoft 365 tenant), an inferred
// "teams" oracle line is appended to the Discovered Services block. The teams
// entry is display/inference only — it is never enumerated unauthenticated.
func outputDNSReconHuman(result *enum.DNSReconResult, teamsAvailable, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "DNS TXT Recon: "+result.Domain))
	fmt.Printf("  Records found: %d\n", len(result.Records))

	if len(result.Services) == 0 && !teamsAvailable {
		fmt.Printf("  %s No SaaS services identified from TXT records\n", dim(useColor, SymbolInfo))
		return
	}

	fmt.Printf("\n  %s\n", heading(useColor, "Discovered Services"))
	for _, svc := range result.Services {
		fmt.Printf("    %s%-16s%s %s\n",
			colorIf(useColor, ColorGreen), svc.Name, colorIf(useColor, ColorReset),
			dim(useColor, "("+svc.Indicator+")"))
	}
	if teamsAvailable {
		fmt.Printf("    %s%-16s%s %s\n",
			colorIf(useColor, ColorGreen), "teams", colorIf(useColor, ColorReset),
			dim(useColor, "(available: Microsoft 365 tenant — run `brutus enum active teams users` / `audit`)"))
	}
	fmt.Println()
}

// outputDNSReconJSONL writes DNS recon results as JSONL. When teamsAvailable is
// true (the org is a Microsoft 365 tenant), a "teams_available":true field is
// added so machine consumers can see the inferred Teams oracle. No tokens are
// ever emitted, and teams is never added to the enumerated services.
func outputDNSReconJSONL(w io.Writer, result *enum.DNSReconResult, teamsAvailable bool) {
	type dnsReconJSON struct {
		Type     string   `json:"type"`
		Domain   string   `json:"domain"`
		Records  []string `json:"records"`
		Services []struct {
			Name      string `json:"name"`
			Indicator string `json:"indicator"`
		} `json:"services"`
		TeamsAvailable bool `json:"teams_available,omitempty"`
	}

	jr := dnsReconJSON{
		Type:           "dns_recon",
		Domain:         result.Domain,
		Records:        result.Records,
		TeamsAvailable: teamsAvailable,
	}
	for _, svc := range result.Services {
		jr.Services = append(jr.Services, struct {
			Name      string `json:"name"`
			Indicator string `json:"indicator"`
		}{Name: svc.Name, Indicator: svc.Indicator})
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(jr); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding DNS recon JSON: %v\n", err)
	}
}

// outputEnumHuman displays enumeration results in human-readable format.
func outputEnumHuman(results []enum.Result, useColor bool) {
	if len(results) == 0 {
		return
	}

	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Enumeration Results"))

	existsCount := 0
	notExistsCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			errorCount++
			if flagVerbose {
				fmt.Printf("  %s%s ERROR%s  %-40s %-16s %v\n",
					colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
					r.Email, r.Service, r.Error)
			}
		case r.Exists:
			existsCount++
			fmt.Printf("  %s%s EXISTS%s %-40s %-16s %s(%s, %s)%s\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Email, r.Service,
				colorIf(useColor, ColorDim), r.Confidence, r.Duration, colorIf(useColor, ColorReset))
		default:
			notExistsCount++
			if !flagQuiet {
				fmt.Printf("  %s[ ] NOT FOUND%s %-36s %-16s %s(%s)%s\n",
					colorIf(useColor, ColorDim), colorIf(useColor, ColorReset),
					r.Email, r.Service,
					colorIf(useColor, ColorDim), r.Duration, colorIf(useColor, ColorReset))
			}
		}
	}

	// Summary
	fmt.Printf("\n  %s\n", heading(useColor, "Summary"))
	if existsCount > 0 {
		fmt.Printf("    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), existsCount)
	}
	if notExistsCount > 0 {
		fmt.Printf("    %sNot found:%s  %d\n", colorIf(useColor, ColorDim), colorIf(useColor, ColorReset), notExistsCount)
	}
	if errorCount > 0 {
		fmt.Printf("    %sErrors:%s     %d\n", colorIf(useColor, ColorRed), colorIf(useColor, ColorReset), errorCount)
	}
	fmt.Printf("    %sTotal:%s      %d\n", colorIf(useColor, ColorCyan), colorIf(useColor, ColorReset), len(results))
	fmt.Println()
}

// outputCandidateOraclesHuman prints the supporting one-liner that explains WHY
// the org's oracles are candidates: the oracles surfaced by DNS TXT recon. It is
// deliberately terse — the headline is the Oracle Check block, not the recon.
// The full TXT detail is available under --verbose (outputDNSReconHuman) and in
// JSON. When teamsAvailable is true (the org is a Microsoft 365 tenant), the
// inferred "teams" oracle is appended to the candidate list.
func outputCandidateOraclesHuman(result *enum.DNSReconResult, teamsAvailable, useColor bool) {
	var candidates []string
	for _, svc := range result.Services {
		candidates = append(candidates, svc.Name)
	}
	if teamsAvailable {
		candidates = append(candidates, "teams")
	}

	if len(candidates) == 0 {
		fmt.Printf("\n%s Discovered no candidate oracles via DNS for %s\n",
			dim(useColor, SymbolInfo), result.Domain)
		return
	}

	fmt.Printf("\n%s Discovered candidate oracles via DNS: %s\n",
		dim(useColor, SymbolInfo), strings.Join(candidates, ", "))
}

// outputOracleCheckHuman renders the headline Oracle Check report: every oracle
// that was checked against the known-valid user and whether it WORKED or NOT.
// This is the prominent, labeled block the oracles command leads with. The
// plugin oracles come from results (Exists -> "[+] working"; otherwise
// "[-] not working"; errored -> "[-] not working (error)"), and the Teams oracle
// is rendered from teamsLine when present (reusing confirmTeamsOracle's
// discover-style mapping: working / available-unconfirmed / not found /
// unconfirmed). Token values never appear in the output.
func outputOracleCheckHuman(label, knownValid string, results []enum.Result, teamsLine string, useColor bool) {
	fmt.Printf("\n%s\n",
		heading(useColor, fmt.Sprintf("=== Oracle Check: %s (validated against %s) ===", label, knownValid)))

	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			fmt.Printf("  %-16s %s%s not working%s (error: %v)\n",
				r.Service,
				colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
				r.Error)
		case r.Exists:
			fmt.Printf("  %-16s %s%s working%s\n",
				r.Service,
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset))
		default:
			fmt.Printf("  %-16s %s%s not working%s\n",
				r.Service,
				colorIf(useColor, ColorYellow), SymbolError, colorIf(useColor, ColorReset))
		}
	}

	if teamsLine != "" {
		name, status, working := parseTeamsOracleLine(teamsLine)
		symbol, color := SymbolSuccess, ColorGreen
		if !working {
			symbol, color = SymbolError, ColorYellow
		}
		fmt.Printf("  %-16s %s%s %s%s\n",
			name, colorIf(useColor, color), symbol, status, colorIf(useColor, ColorReset))
	}

	fmt.Println()
}

// parseTeamsOracleLine splits a confirmTeamsOracle status line (e.g.
// "teams: working (account exists; external detail restricted)") into the oracle
// name, the status remainder, and whether it represents a working oracle. A line
// is "working" when its status begins with "working" (a 200 hit or a 403/blocked
// hit, both of which distinguish real from fake accounts). "available
// (unconfirmed)", "responded, known-valid not found", and "unconfirmed ..." are
// not working.
func parseTeamsOracleLine(line string) (name, status string, working bool) {
	name = "teams"
	status = line
	if idx := strings.Index(line, ":"); idx >= 0 {
		name = strings.TrimSpace(line[:idx])
		status = strings.TrimSpace(line[idx+1:])
	}
	working = strings.HasPrefix(status, "working")
	return name, status, working
}

// outputOracleValidationHuman renders the Oracle Check block for the discover
// subcommand: every oracle tested against the known-valid user and whether it
// WORKED or NOT. It shares the working/not-working mapping with
// outputOracleCheckHuman but, lacking the domain/targets label and Teams line
// (the discover caller prints the Teams line separately), keeps a simple header.
func outputOracleValidationHuman(results []enum.Result, useColor bool) {
	fmt.Printf("\n%s\n", heading(useColor, "=== Oracle Check ==="))
	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			fmt.Printf("  %-16s %s%s not working%s (error: %v)\n",
				r.Service,
				colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
				r.Error)
		case r.Exists:
			fmt.Printf("  %-16s %s%s working%s\n",
				r.Service,
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset))
		default:
			fmt.Printf("  %-16s %s%s not working%s\n",
				r.Service,
				colorIf(useColor, ColorYellow), SymbolError, colorIf(useColor, ColorReset))
		}
	}
	fmt.Println()
}

// outputEnumJSONL writes enumeration results as JSONL.
func outputEnumJSONL(w io.Writer, results []enum.Result) {
	type enumResultJSON struct {
		Type       string `json:"type"`
		Service    string `json:"service"`
		Email      string `json:"email"`
		Exists     bool   `json:"exists"`
		Confidence string `json:"confidence,omitempty"`
		Error      string `json:"error,omitempty"`
		Duration   string `json:"duration"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := enumResultJSON{
			Type:       "enum",
			Service:    r.Service,
			Email:      r.Email,
			Exists:     r.Exists,
			Confidence: string(r.Confidence),
			Duration:   r.Duration.String(),
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding enum JSON: %v\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Hunter.io output functions
// ---------------------------------------------------------------------------

// sanitizeTerminal strips C0/C1 control code points, ESC (U+001B), and full
// ANSI/VT100 escape sequences from s before rendering attacker-controlled
// strings in the human table (P0-4 security requirement). It decodes
// rune-by-rune via utf8.DecodeRune so that valid non-ASCII UTF-8 (e.g. accented
// Latin, CJK) is preserved while raw invalid bytes and genuine control code
// points are dropped. encoding/json already escapes control chars, so JSONL
// output is safe.
func sanitizeTerminal(s string) string {
	var out strings.Builder
	i := 0
	b := []byte(s)
	for i < len(b) {
		r, size := utf8.DecodeRune(b[i:])
		// Invalid UTF-8 byte (raw C1, etc.) — drop single byte.
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		// C0 control code points (U+0000-U+001F), which includes ESC (U+001B) —
		// strip, then consume any escape sequence payload that follows ESC.
		if r < 0x20 {
			i += size
			if r == 0x1B && i < len(b) {
				next := b[i]
				switch next {
				case '[':
					// CSI sequence: consume up through the final byte (A-Z, a-z, or @).
					i++ // skip '['
					for i < len(b) {
						ch := b[i]
						i++
						if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '@' {
							break
						}
					}
				case ']':
					// OSC sequence: consume until ST (ESC \\) or BEL.
					i++
					for i < len(b) {
						ch := b[i]
						i++
						if ch == 0x07 {
							break
						}
						if ch == 0x1B {
							// ST is the two-byte sequence ESC \\; consume the trailing backslash.
							if i < len(b) && b[i] == '\\' {
								i++
							}
							break
						}
					}
				default:
					// Lone ESC (followed by a printable char, not [ or ]): strip
					// only the ESC itself. The next byte stays — it is NOT part of
					// a recognized escape sequence and must be kept.
				}
			}
			continue
		}
		// C1 control code points (U+0080-U+009F, valid 2-byte UTF-8) — strip.
		if r >= 0x80 && r <= 0x9F {
			i += size
			continue
		}
		// Keep valid rune.
		out.WriteRune(r)
		i += size
	}
	return out.String()
}

// truncate shortens s to at most n runes, appending "\u2026" (…) when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "\u2026"
}

// outputHunterHuman renders Hunter.io domain search results as an aligned table.
// All attacker-controlled strings are sanitized via sanitizeTerminal (P0-4).
func outputHunterHuman(w io.Writer, result *hunter.DomainResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Hunter.io: "+sanitizeTerminal(result.Domain)))
	if result.Organization != "" {
		_, _ = fmt.Fprintf(w, "  Organization: %s\n", sanitizeTerminal(result.Organization))
	}
	_, _ = fmt.Fprintf(w, "  People found: %d (total available: %d)\n", len(result.People), result.Total)

	if len(result.People) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No people found for this domain\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	// Header row.
	_, _ = fmt.Fprintf(w, "\n  %s%-32s %-22s %-18s %-14s %-12s %-20s %-5s%s\n",
		colorIf(useColor, ColorBold),
		"Email", "Name", "Title", "Phone", "Dept", "LinkedIn", "Conf",
		colorIf(useColor, ColorReset))

	for i := range result.People {
		p := &result.People[i]
		name := strings.TrimSpace(sanitizeTerminal(p.FirstName) + " " + sanitizeTerminal(p.LastName))
		_, _ = fmt.Fprintf(w, "  %s%-32s%s %-22s %-18s %-14s %-12s %-20s %s%3d%s\n",
			colorIf(useColor, ColorGreen),
			truncate(sanitizeTerminal(p.Email), 32),
			colorIf(useColor, ColorReset),
			truncate(name, 22),
			truncate(sanitizeTerminal(p.Position), 18),
			truncate(sanitizeTerminal(p.Phone), 14),
			truncate(sanitizeTerminal(p.Department), 12),
			truncate(sanitizeTerminal(p.LinkedIn), 20),
			colorIf(useColor, ColorCyan), p.Confidence, colorIf(useColor, ColorReset))
	}
	_, _ = fmt.Fprintln(w)
}

// outputHunterJSONL writes one JSON object per discovered person.
// encoding/json already escapes control characters, so no sanitization needed.
func outputHunterJSONL(w io.Writer, result *hunter.DomainResult) {
	type hunterJSON struct {
		Type         string   `json:"type"`
		Domain       string   `json:"domain"`
		Organization string   `json:"organization,omitempty"`
		Email        string   `json:"email"`
		FirstName    string   `json:"first_name,omitempty"`
		LastName     string   `json:"last_name,omitempty"`
		Position     string   `json:"position,omitempty"`
		Seniority    string   `json:"seniority,omitempty"`
		Department   string   `json:"department,omitempty"`
		Phone        string   `json:"phone_number,omitempty"`
		LinkedIn     string   `json:"linkedin,omitempty"`
		Twitter      string   `json:"twitter,omitempty"`
		Confidence   int      `json:"confidence"`
		EmailType    string   `json:"email_type,omitempty"`
		Sources      []string `json:"sources,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range result.People {
		p := &result.People[i]
		jr := hunterJSON{
			Type:         "hunter",
			Domain:       result.Domain,
			Organization: result.Organization,
			Email:        p.Email,
			FirstName:    p.FirstName,
			LastName:     p.LastName,
			Position:     p.Position,
			Seniority:    p.Seniority,
			Department:   p.Department,
			Phone:        p.Phone,
			LinkedIn:     p.LinkedIn,
			Twitter:      p.Twitter,
			Confidence:   p.Confidence,
			EmailType:    p.Type,
			Sources:      p.Sources,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding hunter JSON: %v\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Teams (Microsoft Entra ID device code) output functions
// ---------------------------------------------------------------------------

// outputTeamsDeviceCodeHuman prints device code auth instructions.
// All server-provided strings are sanitized via sanitizeTerminal (P0-4).
func outputTeamsDeviceCodeHuman(w io.Writer, dc *teams.DeviceCode, useColor bool) {
	uri := sanitizeTerminal(dc.VerificationURI)
	code := sanitizeTerminal(dc.UserCode)

	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Microsoft device code authentication"))
	_, _ = fmt.Fprintf(w, "  Open: %s%s%s\n", colorIf(useColor, ColorCyan), uri, colorIf(useColor, ColorReset))
	_, _ = fmt.Fprintf(w, "  Code: %s%s%s\n", colorIf(useColor, ColorBold), code, colorIf(useColor, ColorReset))
	if dc.Message != "" {
		_, _ = fmt.Fprintf(w, "  %s\n", dim(useColor, sanitizeTerminal(dc.Message)))
	}
	if dc.ExpiresIn > 0 {
		_, _ = fmt.Fprintf(w, "  Expires in: %dm\n", dc.ExpiresIn/60)
	}
	_, _ = fmt.Fprintf(w, "\n  %s Waiting for you to complete sign-in...\n\n", dim(useColor, SymbolInfo))
}

// outputTeamsTokenHuman prints a summary of the token set. Full token values
// are never printed — long tokens are truncated to a short prefix and short
// tokens are shown only as <present>, so usable credentials never leak (P0-1).
func outputTeamsTokenHuman(w io.Writer, tok *teams.TokenSet, useColor bool) {
	_, _ = fmt.Fprintf(w, "%s%s Authentication successful%s\n",
		colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset))
	_, _ = fmt.Fprintf(w, "  Token type:   %s\n", sanitizeTerminal(tok.TokenType))
	_, _ = fmt.Fprintf(w, "  Expires at:   %s\n", tok.ExpiresAt.Format(time.RFC3339))
	if tok.Scope != "" {
		_, _ = fmt.Fprintf(w, "  Scope:        %s\n", sanitizeTerminal(tok.Scope))
	}
	_, _ = fmt.Fprintf(w, "  Access token: %s\n", tokenPreview(tok.AccessToken))
	_, _ = fmt.Fprintf(w, "  Refresh token: %s\n", presence(tok.RefreshToken))
	_, _ = fmt.Fprintf(w, "  ID token:     %s\n", presence(tok.IDToken))
	_, _ = fmt.Fprintln(w)
}

// outputTeamsTokenJSONL writes the full TokenSet as a single JSON line. The
// JSON shape (teamsTokenJSON) is shared with saveTeamsTokenFile so the -o sink
// and the default credential store stay byte-compatible. encoding/json escapes
// control characters, so no sanitization is needed.
func outputTeamsTokenJSONL(w io.Writer, tok *teams.TokenSet) {
	enc := json.NewEncoder(w)
	if err := enc.Encode(newTeamsTokenJSON(tok)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error encoding teams token JSON: %v\n", err)
	}
}

// ---------------------------------------------------------------------------
// Teams user enumeration output functions
// ---------------------------------------------------------------------------

// outputTeamsEnumHuman renders Teams user enumeration results as an aligned
// table. All server-provided strings are sanitized via sanitizeTerminal (P0-4).
// The presence columns (Availability, Device) are shown only when at least one
// result carries presence data.
func outputTeamsEnumHuman(w io.Writer, results []teams.EnumResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Teams User Enumeration"))

	showPresence := false
	for i := range results {
		if results[i].Availability != "" || results[i].DeviceType != "" {
			showPresence = true
			break
		}
	}

	// Header row.
	if showPresence {
		_, _ = fmt.Fprintf(w, "\n  %s%-32s %-12s %-28s %-40s %-14s %-12s%s\n",
			colorIf(useColor, ColorBold),
			"Email", "Status", "Display Name", "MRI", "Availability", "Device",
			colorIf(useColor, ColorReset))
	} else {
		_, _ = fmt.Fprintf(w, "\n  %s%-32s %-12s %-28s %-40s%s\n",
			colorIf(useColor, ColorBold),
			"Email", "Status", "Display Name", "MRI",
			colorIf(useColor, ColorReset))
	}

	for i := range results {
		r := &results[i]
		switch r.Exists {
		case teams.ExistenceNo:
			if flagQuiet {
				continue
			}
		case teams.ExistenceUnknown:
			if !flagVerbose {
				continue
			}
		}

		statusCol, statusColor := teamsEnumStatusLabel(r.Exists)
		email := truncate(sanitizeTerminal(r.Email), 32)
		name := truncate(sanitizeTerminal(r.DisplayName), 28)
		mri := truncate(sanitizeTerminal(r.MRI), 40)

		if showPresence {
			_, _ = fmt.Fprintf(w, "  %-32s %s%-12s%s %-28s %-40s %-14s %-12s\n",
				email,
				colorIf(useColor, statusColor), statusCol, colorIf(useColor, ColorReset),
				name, mri,
				truncate(sanitizeTerminal(r.Availability), 14),
				truncate(sanitizeTerminal(r.DeviceType), 12))
		} else {
			_, _ = fmt.Fprintf(w, "  %-32s %s%-12s%s %-28s %-40s\n",
				email,
				colorIf(useColor, statusColor), statusCol, colorIf(useColor, ColorReset),
				name, mri)
		}
	}

	outputTeamsEnumSummary(w, results, useColor)
}

// outputTeamsEnumResultLine prints ONE Teams enumeration result row in the same
// visual style as outputTeamsEnumHuman's per-row rendering: Email, status label,
// Display Name, and MRI, with the account type appended for EXISTS rows (e.g.
// "(corporate)" or "(consumer)") via teams.AccountType. A 403/blocked result is
// a confirmed hit whose details the tenant withholds, so it renders as an
// "[+] EXISTS" row with a "(details restricted)" qualifier and no
// DisplayName/MRI/account-type (a 403 carries none). All server-provided strings
// are sanitized via sanitizeTerminal (P0-4). Token values are never printed.
// Callers decide which results to print (e.g. positive signals only, unless
// verbose); this helper renders whatever it is given.
func outputTeamsEnumResultLine(w io.Writer, r *teams.EnumResult, useColor bool) {
	statusCol, statusColor := teamsEnumStatusLabel(r.Exists)
	email := truncate(sanitizeTerminal(r.Email), 32)
	name := truncate(sanitizeTerminal(r.DisplayName), 28)
	mri := truncate(sanitizeTerminal(r.MRI), 40)

	// A 403/blocked result is presented as a confirmed EXISTS hit with no
	// metadata, since a 403 carries no DisplayName/MRI/account type.
	if r.Exists == teams.ExistenceBlocked {
		statusCol, statusColor = "[+] EXISTS", ColorGreen
		name, mri = "", ""
	}

	acct := ""
	switch r.Exists {
	case teams.ExistenceYes:
		if t := teams.AccountType(r.MRI); t != "" {
			acct = " (" + t + ")"
		}
	case teams.ExistenceBlocked:
		acct = " (details restricted)"
	}

	_, _ = fmt.Fprintf(w, "  %-32s %s%-12s%s %-28s %-40s%s\n",
		email,
		colorIf(useColor, statusColor), statusCol, colorIf(useColor, ColorReset),
		name, mri, dim(useColor, acct))
}

// outputTeamsEnumSummary prints the counts-by-status summary block for a set of
// Teams enumeration results. A 403/blocked result is a confirmed hit whose
// details the tenant withholds, so the headline "Exists" count is the sum of
// ExistenceYes (200 + data) and ExistenceBlocked (403), with the split shown
// as "(N with details, M details-restricted)". Not-found / errors / total are
// reported as before.
func outputTeamsEnumSummary(w io.Writer, results []teams.EnumResult, useColor bool) {
	var withDetailsCount, restrictedCount, notFoundCount, errorCount int
	for i := range results {
		switch results[i].Exists {
		case teams.ExistenceYes:
			withDetailsCount++
		case teams.ExistenceBlocked:
			restrictedCount++
		case teams.ExistenceNo:
			notFoundCount++
		default:
			errorCount++
		}
	}
	existsCount := withDetailsCount + restrictedCount

	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Summary"))
	if existsCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sExists:%s     %d (%d with details, %d details-restricted)\n",
			colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset),
			existsCount, withDetailsCount, restrictedCount)
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

// teamsEnumStatusLabel maps a tri-state existence to a display label and color.
func teamsEnumStatusLabel(e teams.Existence) (label, color string) {
	switch e {
	case teams.ExistenceYes:
		return "[+] EXISTS", ColorGreen
	case teams.ExistenceBlocked:
		return "[!] BLOCKED", ColorYellow
	case teams.ExistenceNo:
		return "[ ] NOT FOUND", ColorDim
	default:
		return "[x] ERROR", ColorRed
	}
}

// outputTeamsEnumJSONL writes one JSON object per result. Token fields are
// never included. encoding/json escapes control characters, so no sanitization
// is needed.
func outputTeamsEnumJSONL(w io.Writer, results []teams.EnumResult) {
	type teamsEnumJSON struct {
		Type              string `json:"type"`
		Email             string `json:"email"`
		Exists            string `json:"exists"`
		DetailsRestricted bool   `json:"details_restricted,omitempty"`
		DisplayName       string `json:"display_name,omitempty"`
		MRI               string `json:"mri,omitempty"`
		AccountType       string `json:"account_type,omitempty"`
		Availability      string `json:"availability,omitempty"`
		DeviceType        string `json:"device_type,omitempty"`
		Error             string `json:"error,omitempty"`
		UserType          string `json:"user_type,omitempty"`
		TenantID          string `json:"tenant_id,omitempty"`
		UserPrincipalName string `json:"user_principal_name,omitempty"`
		ObjectID          string `json:"object_id,omitempty"`
		AccountEnabled    *bool  `json:"account_enabled,omitempty"`
		CoExistenceMode   string `json:"coexistence_mode,omitempty"`
		SourceNetwork     string `json:"source_network,omitempty"`
		OutOfOfficeNote   string `json:"out_of_office_note,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := teamsEnumJSON{
			Type:  "teams_enum",
			Email: r.Email,
		}
		// Map internal existence to the output shape. A 403/blocked result is a
		// confirmed hit whose details the tenant withholds, so it is presented as
		// "exists":"yes" with "details_restricted":true and no metadata fields (a
		// 403 carries none).
		switch r.Exists {
		case teams.ExistenceBlocked:
			jr.Exists = string(teams.ExistenceYes)
			jr.DetailsRestricted = true
		default:
			jr.Exists = string(r.Exists)
			jr.DisplayName = r.DisplayName
			jr.MRI = r.MRI
			jr.AccountType = teams.AccountType(r.MRI)
			jr.Availability = r.Availability
			jr.DeviceType = r.DeviceType
			jr.UserType = r.Type
			jr.TenantID = r.TenantID
			jr.UserPrincipalName = r.UserPrincipalName
			jr.ObjectID = r.ObjectID
			jr.AccountEnabled = r.AccountEnabled
			jr.CoExistenceMode = r.CoExistenceMode
			jr.SourceNetwork = r.SourceNetwork
			jr.OutOfOfficeNote = r.OutOfOfficeNote
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding teams enum JSON: %v\n", err)
		}
	}
}

// outputTeamsPostureHuman prints a tenant-configuration posture summary block.
// The "External / cross-tenant chat: ALLOWED" line is a finding and is colored
// red when open, green when blocked, and dim when unknown. The server-derived
// coexistence mode is sanitized via sanitizeTerminal (P0-4).
func outputTeamsPostureHuman(w io.Writer, p *teams.TenantPosture, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Teams posture: "+sanitizeTerminal(p.Domain)))

	var chatLabel, chatColor string
	switch p.ExternalChatAllowed {
	case "open":
		chatLabel, chatColor = "ALLOWED", ColorRed
	case "blocked":
		chatLabel, chatColor = "BLOCKED", ColorGreen
	default:
		chatLabel, chatColor = "UNKNOWN", ColorDim
	}

	_, _ = fmt.Fprintf(w, "  External / cross-tenant chat: %s%s%s   (%d users resolvable, %d blocked)\n",
		colorIf(useColor, chatColor), chatLabel, colorIf(useColor, ColorReset),
		p.UsersFound, p.Blocked403)
	_, _ = fmt.Fprintf(w, "  Federation observed:          %s\n", yesNo(p.FederatedObserved))
	_, _ = fmt.Fprintf(w, "  Presence visible externally:  %s\n", yesNo(p.PresenceVisible))
	_, _ = fmt.Fprintf(w, "  Out-of-office notes exposed:  %d\n", p.OOOExposed)

	coex := p.CoExistenceMode
	if coex == "" {
		coex = "unknown"
	} else {
		coex = sanitizeTerminal(coex)
	}
	_, _ = fmt.Fprintf(w, "  Coexistence mode:             %s\n", coex)
	_, _ = fmt.Fprintln(w)
}

// outputTeamsPostureJSONL writes the tenant posture as a single JSON object.
// encoding/json escapes control characters, so no sanitization is needed.
func outputTeamsPostureJSONL(w io.Writer, p *teams.TenantPosture) {
	type teamsPostureJSON struct {
		Type                string `json:"type"`
		Domain              string `json:"domain"`
		Total               int    `json:"total"`
		UsersFound          int    `json:"users_found"`
		Blocked403          int    `json:"blocked_403"`
		ExternalChatAllowed string `json:"external_chat_allowed"`
		FederatedObserved   bool   `json:"federated_observed"`
		PresenceVisible     bool   `json:"presence_visible"`
		OOOExposed          int    `json:"ooo_exposed"`
		CoExistenceMode     string `json:"coexistence_mode,omitempty"`
	}

	jr := teamsPostureJSON{
		Type:                "teams_posture",
		Domain:              p.Domain,
		Total:               p.Total,
		UsersFound:          p.UsersFound,
		Blocked403:          p.Blocked403,
		ExternalChatAllowed: p.ExternalChatAllowed,
		FederatedObserved:   p.FederatedObserved,
		PresenceVisible:     p.PresenceVisible,
		OOOExposed:          p.OOOExposed,
		CoExistenceMode:     p.CoExistenceMode,
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(jr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error encoding teams posture JSON: %v\n", err)
	}
}

// ---------------------------------------------------------------------------
// Teams audit (graded findings) output functions
// ---------------------------------------------------------------------------

// auditEvidenceMaxRunes bounds how much server-derived evidence (e.g. an
// out-of-office note) is rendered in the human report.
const auditEvidenceMaxRunes = 200

// outputTeamsAuditHuman renders graded Teams audit findings as a human report.
// Every server-derived string (Evidence and Affected may contain the OOO note
// or display data) is sanitized via sanitizeTerminal and long evidence is
// truncated (P0-4). Each finding is shown as "[SEVERITY] Title" with a
// severity-appropriate color, followed by indented Evidence and Remediation
// lines, and the run ends with a counts-by-severity summary. The posture block
// is always printed first for context.
func outputTeamsAuditHuman(w io.Writer, domain string, posture *teams.TenantPosture, findings []teams.Finding, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s\n", heading(useColor, "=== Teams Audit: "+sanitizeTerminal(domain)+" ==="))

	outputTeamsPostureHuman(w, posture, useColor)

	if len(findings) == 0 {
		_, _ = fmt.Fprintf(w, "  %s%s No findings — external Teams exposure looks restricted.%s\n\n",
			colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset))
		return
	}

	for i := range findings {
		f := &findings[i]
		color := teamsAuditSeverityColor(f.Severity)
		label := strings.ToUpper(string(f.Severity))

		_, _ = fmt.Fprintf(w, "  %s[%s]%s %s\n",
			colorIf(useColor, color), label, colorIf(useColor, ColorReset),
			sanitizeTerminal(f.Title))
		if f.Affected != "" {
			_, _ = fmt.Fprintf(w, "    Affected:    %s\n", sanitizeTerminal(f.Affected))
		}
		if f.Evidence != "" {
			_, _ = fmt.Fprintf(w, "    Evidence:    %s\n",
				truncate(sanitizeTerminal(f.Evidence), auditEvidenceMaxRunes))
		}
		if f.Remediation != "" {
			_, _ = fmt.Fprintf(w, "    Remediation: %s\n", sanitizeTerminal(f.Remediation))
		}
		_, _ = fmt.Fprintln(w)
	}

	outputTeamsAuditSummary(w, findings, useColor)
}

// outputTeamsAuditSummary prints a counts-by-severity line for the findings.
func outputTeamsAuditSummary(w io.Writer, findings []teams.Finding, useColor bool) {
	var high, medium, low, info int
	for i := range findings {
		switch findings[i].Severity {
		case teams.SeverityHigh:
			high++
		case teams.SeverityMedium:
			medium++
		case teams.SeverityLow:
			low++
		default:
			info++
		}
	}

	_, _ = fmt.Fprintf(w, "  %s %d finding(s): %s%d high%s, %s%d medium%s, %s%d low%s, %s%d info%s\n\n",
		heading(useColor, "Summary:"), len(findings),
		colorIf(useColor, ColorRed), high, colorIf(useColor, ColorReset),
		colorIf(useColor, ColorRed), medium, colorIf(useColor, ColorReset),
		colorIf(useColor, ColorYellow), low, colorIf(useColor, ColorReset),
		colorIf(useColor, ColorDim), info, colorIf(useColor, ColorReset))
}

// teamsAuditSeverityColor maps a finding severity to its display color.
func teamsAuditSeverityColor(s teams.Severity) string {
	switch s {
	case teams.SeverityHigh:
		return ColorRed
	case teams.SeverityMedium:
		return ColorRed
	case teams.SeverityLow:
		return ColorYellow
	default:
		return ColorDim
	}
}

// outputTeamsAuditJSONL writes one JSON object per finding. Token values are
// never included. encoding/json escapes control characters, so no sanitization
// is needed.
func outputTeamsAuditJSONL(w io.Writer, findings []teams.Finding) {
	type teamsFindingJSON struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Evidence    string `json:"evidence,omitempty"`
		Affected    string `json:"affected,omitempty"`
		Remediation string `json:"remediation,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range findings {
		f := &findings[i]
		jr := teamsFindingJSON{
			Type:        "teams_finding",
			ID:          f.ID,
			Title:       f.Title,
			Severity:    string(f.Severity),
			Description: f.Description,
			Evidence:    f.Evidence,
			Affected:    f.Affected,
			Remediation: f.Remediation,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding teams finding JSON: %v\n", err)
		}
	}
}

// yesNo renders a bool as "yes"/"no" for posture summary rows.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// tokenPreview renders a token for human output without leaking it (P0-1):
// "<absent>" for empty, "<present>" for tokens of 20 runes or fewer, and the
// sanitized first 20 runes plus "..." for longer tokens.
func tokenPreview(token string) string {
	token = sanitizeTerminal(token)
	if token == "" {
		return "<absent>"
	}
	r := []rune(token)
	if len(r) <= 20 {
		return "<present>"
	}
	return string(r[:20]) + "..."
}

// presence reports whether a token value is present without revealing it.
func presence(token string) string {
	if token == "" {
		return "<absent>"
	}
	return "<present>"
}

// ---------------------------------------------------------------------------
// Google Workspace account enumeration output functions
// ---------------------------------------------------------------------------

// outputGoogleEnumResultLine prints ONE Google enumeration result row. EXISTS
// rows show the email, an "[+] EXISTS" label, and a method note: workspace-sso
// renders as " (workspace-sso -> <IdP>)" (or just " (workspace-sso)" when the
// IdP is empty), gmail as " (gmail)". Not-found rows render as "[ ] not found".
// The server-controlled IdP host is sanitized via sanitizeTerminal (P0-4).
// Callers decide which results to print (e.g. EXISTS only, unless verbose); this
// helper renders whatever it is given.
func outputGoogleEnumResultLine(w io.Writer, r google.Result, useColor bool) {
	email := truncate(sanitizeTerminal(r.Email), 40)

	if !r.Exists {
		_, _ = fmt.Fprintf(w, "  %-40s %s[ ] not found%s\n",
			email, colorIf(useColor, ColorDim), colorIf(useColor, ColorReset))
		return
	}

	note := ""
	switch r.Method {
	case google.MethodWorkspaceSSO:
		if r.IdP != "" {
			note = " (workspace-sso -> " + sanitizeTerminal(r.IdP) + ")"
		} else {
			note = " (workspace-sso)"
		}
	case google.MethodGmail:
		note = " (gmail)"
	}

	_, _ = fmt.Fprintf(w, "  %-40s %s%s EXISTS%s%s\n",
		email,
		colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
		dim(useColor, note))
}

// outputGoogleEnumSummary prints the counts-by-status summary block for a set
// of Google enumeration results: found / not found / errors / total.
func outputGoogleEnumSummary(w io.Writer, results []google.Result, useColor bool) {
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

// outputGoogleEnumJSONL writes one JSON object per result. encoding/json escapes
// control characters, so no sanitization is needed.
func outputGoogleEnumJSONL(w io.Writer, results []google.Result) {
	type googleEnumJSON struct {
		Type   string `json:"type"`
		Email  string `json:"email"`
		Exists bool   `json:"exists"`
		Method string `json:"method,omitempty"`
		IdP    string `json:"idp,omitempty"`
		Error  string `json:"error,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		jr := googleEnumJSON{
			Type:   "google_account",
			Email:  r.Email,
			Exists: r.Exists,
			Method: string(r.Method),
			IdP:    r.IdP,
		}
		if r.Error != nil {
			jr.Error = r.Error.Error()
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding google enum JSON: %v\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Microsoft 365 account enumeration output functions
// ---------------------------------------------------------------------------

// microsoft365ExistsNote builds the parenthetical annotation for an EXISTS row:
// the tenant relationship the GetCredentialType API reveals and, when the
// tenant is federated, the identity-provider host the sign-in redirects to.
// The server-controlled FederationURL is sanitized (P0-4) before rendering.
func microsoft365ExistsNote(r m365.Result) string { //nolint:gocritic // hugeParam: Result passed by value to mirror the Google enum output helpers and keep call sites simple
	var parts []string
	switch r.IfExistsResult {
	case m365.IfExistsResultExists:
		parts = append(parts, "managed")
	case m365.IfExistsResultDifferentTenant:
		parts = append(parts, "different tenant")
	case m365.IfExistsResultDomainHint:
		parts = append(parts, "domain hint")
	}
	if r.Federated {
		host := sanitizeTerminal(microsoft365FederationHost(r.FederationURL))
		if host != "" {
			parts = append(parts, "federated -> "+host)
		} else {
			parts = append(parts, "federated")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// microsoft365FederationHost extracts the host from a federation redirect URL
// for compact display, falling back to the raw string when it does not parse.
func microsoft365FederationHost(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// outputMicrosoft365EnumResultLine prints ONE Microsoft 365 enumeration result
// row. EXISTS rows show the email, an "[+] EXISTS" label, and a note describing
// the tenant relationship (managed / different tenant / domain hint) and any
// federation IdP host. Not-found rows render as "[ ] not found". Callers decide
// which results to print (e.g. EXISTS only, unless verbose).
func outputMicrosoft365EnumResultLine(w io.Writer, r m365.Result, useColor bool) { //nolint:gocritic // hugeParam: Result passed by value to mirror the Google enum output helpers and keep call sites simple
	email := truncate(sanitizeTerminal(r.Email), 40)

	if r.Error != nil {
		// Error messages are constructed by the checker but may wrap
		// transport/server text; sanitize before rendering (P0-4).
		_, _ = fmt.Fprintf(w, "  %-40s %s[!] error:%s %s\n",
			email, colorIf(useColor, ColorRed), colorIf(useColor, ColorReset),
			dim(useColor, sanitizeTerminal(r.Error.Error())))
		return
	}

	if !r.Exists {
		_, _ = fmt.Fprintf(w, "  %-40s %s[ ] not found%s\n",
			email, colorIf(useColor, ColorDim), colorIf(useColor, ColorReset))
		return
	}

	_, _ = fmt.Fprintf(w, "  %-40s %s%s EXISTS%s%s\n",
		email,
		colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
		dim(useColor, microsoft365ExistsNote(r)))
}

// outputMicrosoft365EnumSummary prints the counts-by-status summary block for a
// set of Microsoft 365 enumeration results: found / federated / not found /
// errors / total.
func outputMicrosoft365EnumSummary(w io.Writer, results []m365.Result, useColor bool) {
	var foundCount, federatedCount, notFoundCount, errorCount int
	for i := range results {
		switch {
		case results[i].Error != nil:
			errorCount++
		case results[i].Exists:
			foundCount++
			if results[i].Federated {
				federatedCount++
			}
		default:
			notFoundCount++
		}
	}

	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Summary"))
	if foundCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), foundCount)
	}
	if federatedCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sFederated:%s  %d\n", colorIf(useColor, ColorCyan), colorIf(useColor, ColorReset), federatedCount)
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

// microsoft365EnumJSON is the JSONL shape for one Microsoft 365 enumeration
// result. IfExistsResult is a pointer with omitempty so it is emitted only when
// an actual API code was decoded (i.e. no error): on a pre-response failure the
// zero value 0 would otherwise be indistinguishable from the API's "account
// exists" code, contradicting the accompanying error.
type microsoft365EnumJSON struct {
	Type           string `json:"type"`
	Email          string `json:"email"`
	Exists         bool   `json:"exists"`
	IfExistsResult *int   `json:"if_exists_result,omitempty"`
	Federated      bool   `json:"federated,omitempty"`
	FederationURL  string `json:"federation_url,omitempty"`
	Error          string `json:"error,omitempty"`
}

// encodeMicrosoft365EnumResult encodes ONE Microsoft 365 enumeration result as a
// JSONL line via enc. When the result carries no error, if_exists_result is
// populated with the decoded API code (present even when 0); on error it is left
// nil (omitted) and the error message is emitted instead. encoding/json escapes
// control characters, so no sanitization is needed.
func encodeMicrosoft365EnumResult(enc *json.Encoder, r m365.Result) { //nolint:gocritic // hugeParam: Result passed by value to mirror the sibling enum output helpers and keep call sites simple
	jr := microsoft365EnumJSON{
		Type:          "microsoft365_account",
		Email:         r.Email,
		Exists:        r.Exists,
		Federated:     r.Federated,
		FederationURL: r.FederationURL,
	}
	if r.Error != nil {
		jr.Error = r.Error.Error()
	} else {
		// Fresh var per call so &code never aliases across results.
		code := r.IfExistsResult
		jr.IfExistsResult = &code
	}
	if err := enc.Encode(jr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error encoding microsoft365 enum JSON: %v\n", err)
	}
}

// outputMicrosoft365EnumJSONL writes one JSON object per result, reusing a
// single encoder. encoding/json escapes control characters, so no sanitization
// is needed.
func outputMicrosoft365EnumJSONL(w io.Writer, results []m365.Result) {
	enc := json.NewEncoder(w)
	for i := range results {
		encodeMicrosoft365EnumResult(enc, results[i])
	}
}
