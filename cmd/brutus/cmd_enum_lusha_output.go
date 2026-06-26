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

	"github.com/praetorian-inc/brutus/pkg/enum/lusha"
)

// outputLushaHuman renders a Lusha enriched contact as aligned tables.
// All vendor-controlled strings are sanitized via sanitizeTerminal then
// truncated (P0-4). The per-phone Do-Not-Call flag is surfaced explicitly as a
// DNC marker so the operator can honor suppression (P0-DNC).
func outputLushaHuman(w io.Writer, c *lusha.Contact, useColor bool) {
	summary := lushaIdentitySummary(c)
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Lusha: "+summary))

	if c.JobTitle != "" {
		_, _ = fmt.Fprintf(w, "  Title:    %s\n", truncate(sanitizeTerminal(c.JobTitle), 80))
	}
	if c.Seniority != "" {
		_, _ = fmt.Fprintf(w, "  Seniority: %s\n", truncate(sanitizeTerminal(c.Seniority), 40))
	}
	if len(c.Departments) > 0 {
		_, _ = fmt.Fprintf(w, "  Dept:     %s\n", truncate(sanitizeTerminal(strings.Join(c.Departments, ", ")), 80))
	}
	if c.Company != "" {
		_, _ = fmt.Fprintf(w, "  Company:  %s\n", truncate(sanitizeTerminal(c.Company), 80))
	}
	if c.Location != "" {
		_, _ = fmt.Fprintf(w, "  Location: %s\n", truncate(sanitizeTerminal(c.Location), 60))
	}
	if c.LinkedIn != "" {
		_, _ = fmt.Fprintf(w, "  LinkedIn: %s\n", truncate(sanitizeTerminal(c.LinkedIn), 100))
	}
	if line := lushaEmploymentSummary(c); line != "" {
		_, _ = fmt.Fprintf(w, "  History:  %s\n", line)
	}

	if len(c.Emails) == 0 && len(c.Phones) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No contact data returned\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	if len(c.Emails) > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s%-40s %-12s %-12s%s\n",
			colorIf(useColor, ColorBold),
			"Email", "Type", "Confidence",
			colorIf(useColor, ColorReset))
		for i := range c.Emails {
			e := &c.Emails[i]
			_, _ = fmt.Fprintf(w, "  %s%-40s%s %-12s %-12s\n",
				colorIf(useColor, ColorGreen),
				truncate(sanitizeTerminal(e.Address), 40),
				colorIf(useColor, ColorReset),
				truncate(sanitizeTerminal(e.Type), 12),
				truncate(sanitizeTerminal(e.Confidence), 12))
		}
	}

	if len(c.Phones) > 0 {
		_, _ = fmt.Fprintf(w, "\n  %s%-24s %-12s %-5s%s\n",
			colorIf(useColor, ColorBold),
			"Phone", "Type", "DNC",
			colorIf(useColor, ColorReset))
		for i := range c.Phones {
			p := &c.Phones[i]
			dnc := ""
			if p.DoNotCall {
				dnc = "DNC"
			}
			_, _ = fmt.Fprintf(w, "  %-24s %-12s %s%-5s%s\n",
				truncate(sanitizeTerminal(p.Number), 24),
				truncate(sanitizeTerminal(p.Type), 12),
				colorIf(useColor, ColorYellow), dnc, colorIf(useColor, ColorReset))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// outputLushaJSONL writes the contact as a single JSON line.
// encoding/json already escapes control characters, so no sanitization needed.
// The per-phone do_not_call bool is always emitted to surface DNC (P0-DNC).
func outputLushaJSONL(w io.Writer, c *lusha.Contact) {
	type emailJSON struct {
		Address    string `json:"address"`
		Type       string `json:"type,omitempty"`
		Confidence string `json:"confidence,omitempty"`
	}
	type phoneJSON struct {
		Number    string `json:"number"`
		Type      string `json:"type,omitempty"`
		DoNotCall bool   `json:"do_not_call"`
	}
	type employmentJSON struct {
		Organization string `json:"organization,omitempty"`
		Title        string `json:"title,omitempty"`
		Current      bool   `json:"current"`
	}
	type contactJSON struct {
		Type          string           `json:"type"`
		Name          string           `json:"name,omitempty"`
		JobTitle      string           `json:"job_title,omitempty"`
		Company       string           `json:"company,omitempty"`
		CompanyDomain string           `json:"company_domain,omitempty"`
		LinkedIn      string           `json:"linkedin,omitempty"`
		Departments   []string         `json:"departments,omitempty"`
		Seniority     string           `json:"seniority,omitempty"`
		Location      string           `json:"location,omitempty"`
		Emails        []emailJSON      `json:"emails,omitempty"`
		Phones        []phoneJSON      `json:"phones,omitempty"`
		Employment    []employmentJSON `json:"employment,omitempty"`
	}

	jr := contactJSON{
		Type:          "lusha",
		Name:          c.Name,
		JobTitle:      c.JobTitle,
		Company:       c.Company,
		CompanyDomain: c.CompanyDomain,
		LinkedIn:      c.LinkedIn,
		Departments:   c.Departments,
		Seniority:     c.Seniority,
		Location:      c.Location,
	}
	for i := range c.Emails {
		e := &c.Emails[i]
		jr.Emails = append(jr.Emails, emailJSON{
			Address:    e.Address,
			Type:       e.Type,
			Confidence: e.Confidence,
		})
	}
	for i := range c.Phones {
		p := &c.Phones[i]
		jr.Phones = append(jr.Phones, phoneJSON{
			Number:    p.Number,
			Type:      p.Type,
			DoNotCall: p.DoNotCall,
		})
	}
	for i := range c.Employment {
		em := &c.Employment[i]
		jr.Employment = append(jr.Employment, employmentJSON{
			Organization: em.Organization,
			Title:        em.Title,
			Current:      em.Current,
		})
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(jr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error encoding lusha JSON: %v\n", err)
	}
}

// lushaIdentitySummary builds a short, sanitized label for the contact header.
func lushaIdentitySummary(c *lusha.Contact) string {
	if name := strings.TrimSpace(sanitizeTerminal(c.Name)); name != "" {
		return name
	}
	return "contact"
}

// lushaEmploymentSummary renders employment history compactly for the human
// view: the current organization plus a count of prior roles. Full per-role
// detail is available in JSONL output. Returns "" when no history is present.
func lushaEmploymentSummary(c *lusha.Contact) string {
	current := ""
	prior := 0
	for i := range c.Employment {
		em := &c.Employment[i]
		if em.Current && current == "" {
			current = truncate(sanitizeTerminal(em.Organization), 60)
			continue
		}
		prior++
	}
	switch {
	case current != "" && prior > 0:
		return fmt.Sprintf("%s (+%d prior)", current, prior)
	case current != "":
		return current
	case prior > 0:
		return fmt.Sprintf("%d prior role(s)", prior)
	}
	return ""
}
