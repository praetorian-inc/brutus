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

	"github.com/praetorian-inc/brutus/pkg/enum/apollo"
)

// outputApolloHuman renders Apollo people results as an aligned table.
// All attacker-controlled strings are sanitized via sanitizeTerminal (P0-4).
// Columns adapt on result.Revealed: discovery (free) shows
// Name|Title|Dept|Org|Email?|Phone? where Email?/Phone? render AVAILABILITY
// (✓/–) — not actual values; enriched shows Email|Status|LinkedIn and keeps a
// trailing Phone? AVAILABILITY column (✓/–), since phone is never revealed.
func outputApolloHuman(w io.Writer, result *apollo.DomainResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Apollo: "+sanitizeTerminal(result.Domain)))
	if result.Revealed {
		_, _ = fmt.Fprintf(w, "  People found: %d (total: %d) · credits charged: %d\n",
			len(result.People), result.Total, result.CreditsCharged)
	} else {
		_, _ = fmt.Fprintf(w, "  People found: %d (total: %d)\n", len(result.People), result.Total)
		_, _ = fmt.Fprintf(w, "  %s\n",
			dim(useColor, "(discovery — Email?/Phone? show availability; run with --enrich to reveal emails, consumes credits)"))
	}

	if len(result.People) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No people found for this domain\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	if result.Revealed {
		_, _ = fmt.Fprintf(w, "\n  %s%-28s %-22s %-12s %-22s %-32s %-10s %-32s %-7s%s\n",
			colorIf(useColor, ColorBold),
			"Name", "Title", "Dept", "Org", "Email", "Status", "LinkedIn", "Phone?",
			colorIf(useColor, ColorReset))
	} else {
		_, _ = fmt.Fprintf(w, "\n  %s%-28s %-22s %-12s %-22s %-7s %-7s%s\n",
			colorIf(useColor, ColorBold),
			"Name", "Title", "Dept", "Org", "Email?", "Phone?",
			colorIf(useColor, ColorReset))
	}

	for i := range result.People {
		p := &result.People[i]
		name := personName(p)
		if result.Revealed {
			_, _ = fmt.Fprintf(w, "  %-28s %-22s %-12s %-22s %s%-32s%s %-10s %-32s %-7s\n",
				truncate(name, 28),
				truncate(sanitizeTerminal(p.Title), 22),
				truncate(sanitizeTerminal(p.Department), 12),
				truncate(sanitizeTerminal(p.Organization), 22),
				colorIf(useColor, ColorGreen),
				truncate(sanitizeTerminal(p.Email), 32),
				colorIf(useColor, ColorReset),
				truncate(sanitizeTerminal(p.EmailStatus), 10),
				truncate(sanitizeTerminal(p.LinkedinURL), 32),
				availabilityMark(p.HasPhone))
		} else {
			_, _ = fmt.Fprintf(w, "  %-28s %-22s %-12s %-22s %-7s %-7s\n",
				truncate(name, 28),
				truncate(sanitizeTerminal(p.Title), 22),
				truncate(sanitizeTerminal(p.Department), 12),
				truncate(sanitizeTerminal(p.Organization), 22),
				availabilityMark(p.HasEmail),
				availabilityMark(p.HasPhone))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// availabilityMark renders a discovery-tier availability flag as a check or dash.
// These reflect whether enrichment COULD reveal a value — never an actual value.
func availabilityMark(available bool) string {
	if available {
		return "✓"
	}
	return "–"
}

// outputApolloJSONL writes one JSON object per person. encoding/json already
// escapes control characters, so no sanitization needed. It branches on
// result.Revealed: discovery emits slim candidate objects carrying only the free
// fields plus has_email/has_phone availability (NO email/phone values); enriched
// emits the full record including the revealed fields.
func outputApolloJSONL(w io.Writer, result *apollo.DomainResult) {
	if !result.Revealed {
		outputApolloDiscoverJSONL(w, result)
		return
	}
	type employmentJSON struct {
		Organization string `json:"organization,omitempty"`
		Title        string `json:"title,omitempty"`
		StartDate    string `json:"start_date,omitempty"`
		EndDate      string `json:"end_date,omitempty"`
		Current      bool   `json:"current"`
	}
	type apolloJSON struct {
		Type         string           `json:"type"`
		Domain       string           `json:"domain"`
		Revealed     bool             `json:"revealed"`
		HasEmail     bool             `json:"has_email"`
		HasPhone     bool             `json:"has_phone"`
		ID           string           `json:"id"`
		Name         string           `json:"name,omitempty"`
		FirstName    string           `json:"first_name,omitempty"`
		LastName     string           `json:"last_name,omitempty"`
		Title        string           `json:"title,omitempty"`
		Seniority    string           `json:"seniority,omitempty"`
		Department   string           `json:"department,omitempty"`
		Departments  []string         `json:"departments,omitempty"`
		Organization string           `json:"organization,omitempty"`
		Email        string           `json:"email,omitempty"`
		EmailStatus  string           `json:"email_status,omitempty"`
		LinkedinURL  string           `json:"linkedin_url,omitempty"`
		Twitter      string           `json:"twitter_url,omitempty"`
		City         string           `json:"city,omitempty"`
		State        string           `json:"state,omitempty"`
		Country      string           `json:"country,omitempty"`
		Employment   []employmentJSON `json:"employment,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range result.People {
		p := &result.People[i]
		var employment []employmentJSON
		for j := range p.Employment {
			e := &p.Employment[j]
			employment = append(employment, employmentJSON{
				Organization: e.Organization,
				Title:        e.Title,
				StartDate:    e.StartDate,
				EndDate:      e.EndDate,
				Current:      e.Current,
			})
		}
		jr := apolloJSON{
			Type:         "apollo",
			Domain:       result.Domain,
			Revealed:     p.Revealed,
			HasEmail:     p.HasEmail,
			HasPhone:     p.HasPhone,
			ID:           p.ID,
			Name:         p.Name,
			FirstName:    p.FirstName,
			LastName:     p.LastName,
			Title:        p.Title,
			Seniority:    p.Seniority,
			Department:   p.Department,
			Departments:  p.Departments,
			Organization: p.Organization,
			Email:        p.Email,
			EmailStatus:  p.EmailStatus,
			LinkedinURL:  p.LinkedinURL,
			Twitter:      p.Twitter,
			City:         p.City,
			State:        p.State,
			Country:      p.Country,
			Employment:   employment,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding apollo JSON: %v\n", err)
		}
	}
}

// outputApolloDiscoverJSONL writes one slim candidate object per discovered
// person for the FREE discovery tier: identity fields plus has_email/has_phone
// availability (always present so a consumer can read availability=false), and
// deliberately NO email/phone values (none were revealed). type is "apollo".
func outputApolloDiscoverJSONL(w io.Writer, result *apollo.DomainResult) {
	type apolloCandidateJSON struct {
		Type         string `json:"type"`
		Domain       string `json:"domain"`
		Revealed     bool   `json:"revealed"`
		ID           string `json:"id"`
		Name         string `json:"name,omitempty"`
		FirstName    string `json:"first_name,omitempty"`
		Title        string `json:"title,omitempty"`
		Organization string `json:"organization,omitempty"`
		HasEmail     bool   `json:"has_email"`
		HasPhone     bool   `json:"has_phone"`
	}

	enc := json.NewEncoder(w)
	for i := range result.People {
		p := &result.People[i]
		jr := apolloCandidateJSON{
			Type:         "apollo",
			Domain:       result.Domain,
			Revealed:     false,
			ID:           p.ID,
			Name:         p.Name,
			FirstName:    p.FirstName,
			Title:        p.Title,
			Organization: p.Organization,
			HasEmail:     p.HasEmail,
			HasPhone:     p.HasPhone,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding apollo JSON: %v\n", err)
		}
	}
}

// personName returns the sanitized display name, preferring Apollo's full Name
// and falling back to "First Last".
func personName(p *apollo.Person) string {
	if p.Name != "" {
		return sanitizeTerminal(p.Name)
	}
	return strings.TrimSpace(sanitizeTerminal(p.FirstName) + " " + sanitizeTerminal(p.LastName))
}
