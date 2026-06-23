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
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// outputDNSReconHuman displays DNS TXT recon results in human-readable format.
func outputDNSReconHuman(result *enum.DNSReconResult, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "DNS TXT Recon: "+result.Domain))
	fmt.Printf("  Records found: %d\n", len(result.Records))

	if len(result.Services) == 0 {
		fmt.Printf("  %s No SaaS services identified from TXT records\n", dim(useColor, SymbolInfo))
		return
	}

	fmt.Printf("\n  %s\n", heading(useColor, "Discovered Services"))
	for _, svc := range result.Services {
		fmt.Printf("    %s%-16s%s %s\n",
			colorIf(useColor, ColorGreen), svc.Name, colorIf(useColor, ColorReset),
			dim(useColor, "("+svc.Indicator+")"))
	}
	fmt.Println()
}

// outputDNSReconJSONL writes DNS recon results as JSONL.
func outputDNSReconJSONL(w io.Writer, result *enum.DNSReconResult) {
	type dnsReconJSON struct {
		Type     string   `json:"type"`
		Domain   string   `json:"domain"`
		Records  []string `json:"records"`
		Services []struct {
			Name      string `json:"name"`
			Indicator string `json:"indicator"`
		} `json:"services"`
	}

	jr := dnsReconJSON{
		Type:    "dns_recon",
		Domain:  result.Domain,
		Records: result.Records,
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

// outputOracleValidationHuman displays oracle validation results.
func outputOracleValidationHuman(results []enum.Result, useColor bool) {
	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Oracle Validation"))
	for i := range results {
		r := &results[i]
		switch {
		case r.Error != nil:
			fmt.Printf("  %s%s FAIL%s    %-16s %v\n",
				colorIf(useColor, ColorRed), SymbolError, colorIf(useColor, ColorReset),
				r.Service, r.Error)
		case r.Exists:
			fmt.Printf("  %s%s PASS%s    %-16s confirmed (%s, %s)\n",
				colorIf(useColor, ColorGreen), SymbolSuccess, colorIf(useColor, ColorReset),
				r.Service, r.Confidence, r.Duration)
		default:
			fmt.Printf("  %s%s FAIL%s    %-16s did not confirm known-valid email (%s)\n",
				colorIf(useColor, ColorYellow), SymbolWarning, colorIf(useColor, ColorReset),
				r.Service, r.Duration)
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
	_, _ = fmt.Fprintf(w, "\n  %s%-32s %-22s %-22s %-16s %-12s %-5s%s\n",
		colorIf(useColor, ColorBold),
		"Email", "Name", "Title", "Phone", "Dept", "Conf",
		colorIf(useColor, ColorReset))

	for i := range result.People {
		p := &result.People[i]
		name := strings.TrimSpace(sanitizeTerminal(p.FirstName) + " " + sanitizeTerminal(p.LastName))
		_, _ = fmt.Fprintf(w, "  %s%-32s%s %-22s %-22s %-16s %-12s %s%3d%s\n",
			colorIf(useColor, ColorGreen),
			truncate(sanitizeTerminal(p.Email), 32),
			colorIf(useColor, ColorReset),
			truncate(name, 22),
			truncate(sanitizeTerminal(p.Position), 22),
			truncate(sanitizeTerminal(p.Phone), 16),
			truncate(sanitizeTerminal(p.Department), 12),
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

	var existsCount, blockedCount, notFoundCount, errorCount int

	for i := range results {
		r := &results[i]
		switch r.Exists {
		case teams.ExistenceYes:
			existsCount++
		case teams.ExistenceBlocked:
			blockedCount++
		case teams.ExistenceNo:
			notFoundCount++
			if flagQuiet {
				continue
			}
		default:
			errorCount++
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

	// Summary.
	_, _ = fmt.Fprintf(w, "\n  %s\n", heading(useColor, "Summary"))
	if existsCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sExists:%s     %d\n", colorIf(useColor, ColorGreen), colorIf(useColor, ColorReset), existsCount)
	}
	if blockedCount > 0 {
		_, _ = fmt.Fprintf(w, "    %sBlocked:%s    %d\n", colorIf(useColor, ColorYellow), colorIf(useColor, ColorReset), blockedCount)
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
		DisplayName       string `json:"display_name,omitempty"`
		MRI               string `json:"mri,omitempty"`
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
			Type:              "teams_enum",
			Email:             r.Email,
			Exists:            string(r.Exists),
			DisplayName:       r.DisplayName,
			MRI:               r.MRI,
			Availability:      r.Availability,
			DeviceType:        r.DeviceType,
			UserType:          r.Type,
			TenantID:          r.TenantID,
			UserPrincipalName: r.UserPrincipalName,
			ObjectID:          r.ObjectID,
			AccountEnabled:    r.AccountEnabled,
			CoExistenceMode:   r.CoExistenceMode,
			SourceNetwork:     r.SourceNetwork,
			OutOfOfficeNote:   r.OutOfOfficeNote,
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
func outputTeamsPostureHuman(w io.Writer, p teams.TenantPosture, useColor bool) {
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
func outputTeamsPostureJSONL(w io.Writer, p teams.TenantPosture) {
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
