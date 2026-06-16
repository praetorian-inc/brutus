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
	"unicode/utf8"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
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
				if next == '[' {
					// CSI sequence: consume up through the final byte (A-Z, a-z, or @).
					i++ // skip '['
					for i < len(b) {
						ch := b[i]
						i++
						if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '@' {
							break
						}
					}
				} else if next == ']' {
					// OSC sequence: consume until ST (ESC \\) or BEL.
					i++
					for i < len(b) {
						ch := b[i]
						i++
						if ch == 0x07 || ch == 0x1B {
							break
						}
					}
				} else {
					// Lone ESC (followed by a printable char, not [ or ]): strip
					// only the ESC itself. The next byte stays — it is NOT part of
					// a recognised escape sequence and must be kept.
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

// truncate shortens s to at most max runes, appending "\u2026" (…) when cut.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "\u2026"
}

// outputHunterHuman renders Hunter.io domain search results as an aligned table.
// All attacker-controlled strings are sanitized via sanitizeTerminal (P0-4).
func outputHunterHuman(w io.Writer, result *hunter.DomainResult, useColor bool) {
	fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Hunter.io: "+sanitizeTerminal(result.Domain)))
	if result.Organization != "" {
		fmt.Fprintf(w, "  Organization: %s\n", sanitizeTerminal(result.Organization))
	}
	fmt.Fprintf(w, "  People found: %d (total available: %d)\n", len(result.People), result.Total)

	if len(result.People) == 0 {
		fmt.Fprintf(w, "\n  %s No people found for this domain\n", dim(useColor, SymbolInfo))
		fmt.Fprintln(w)
		return
	}

	// Header row.
	fmt.Fprintf(w, "\n  %s%-32s %-22s %-22s %-16s %-12s %-5s%s\n",
		colorIf(useColor, ColorBold),
		"Email", "Name", "Title", "Phone", "Dept", "Conf",
		colorIf(useColor, ColorReset))

	for i := range result.People {
		p := &result.People[i]
		name := strings.TrimSpace(sanitizeTerminal(p.FirstName) + " " + sanitizeTerminal(p.LastName))
		fmt.Fprintf(w, "  %s%-32s%s %-22s %-22s %-16s %-12s %s%3d%s\n",
			colorIf(useColor, ColorGreen),
			truncate(sanitizeTerminal(p.Email), 32),
			colorIf(useColor, ColorReset),
			truncate(name, 22),
			truncate(sanitizeTerminal(p.Position), 22),
			truncate(sanitizeTerminal(p.Phone), 16),
			truncate(sanitizeTerminal(p.Department), 12),
			colorIf(useColor, ColorCyan), p.Confidence, colorIf(useColor, ColorReset))
	}
	fmt.Fprintln(w)
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
			fmt.Fprintf(os.Stderr, "Error encoding hunter JSON: %v\n", err)
		}
	}
}
