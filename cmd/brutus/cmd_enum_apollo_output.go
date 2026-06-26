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

// outputApolloHuman renders Apollo people-search results as an aligned table.
// All attacker-controlled strings are sanitized via sanitizeTerminal (P0-4).
// Columns adapt: preview (no emails) shows Name|Title|Dept|Org; revealed adds
// Email|Status.
func outputApolloHuman(w io.Writer, result *apollo.DomainResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "Apollo: "+sanitizeTerminal(result.Domain)))
	_, _ = fmt.Fprintf(w, "  People found: %d (total: %d)\n", len(result.People), result.Total)

	if !result.Revealed {
		_, _ = fmt.Fprintf(w, "  %s\n",
			dim(useColor, "(preview — run with --reveal for emails; consumes credits)"))
	}

	if len(result.People) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No people found for this domain\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	if result.Revealed {
		_, _ = fmt.Fprintf(w, "\n  %s%-28s %-22s %-12s %-22s %-32s %-10s %-32s%s\n",
			colorIf(useColor, ColorBold),
			"Name", "Title", "Dept", "Org", "Email", "Status", "LinkedIn",
			colorIf(useColor, ColorReset))
	} else {
		_, _ = fmt.Fprintf(w, "\n  %s%-28s %-22s %-12s %-22s%s\n",
			colorIf(useColor, ColorBold),
			"Name", "Title", "Dept", "Org",
			colorIf(useColor, ColorReset))
	}

	for i := range result.People {
		p := &result.People[i]
		name := personName(p)
		if result.Revealed {
			_, _ = fmt.Fprintf(w, "  %-28s %-22s %-12s %-22s %s%-32s%s %-10s %-32s\n",
				truncate(name, 28),
				truncate(sanitizeTerminal(p.Title), 22),
				truncate(sanitizeTerminal(p.Department), 12),
				truncate(sanitizeTerminal(p.Organization), 22),
				colorIf(useColor, ColorGreen),
				truncate(sanitizeTerminal(p.Email), 32),
				colorIf(useColor, ColorReset),
				truncate(sanitizeTerminal(p.EmailStatus), 10),
				truncate(sanitizeTerminal(p.LinkedinURL), 32))
		} else {
			_, _ = fmt.Fprintf(w, "  %-28s %-22s %-12s %-22s\n",
				truncate(name, 28),
				truncate(sanitizeTerminal(p.Title), 22),
				truncate(sanitizeTerminal(p.Department), 12),
				truncate(sanitizeTerminal(p.Organization), 22))
		}
	}
	_, _ = fmt.Fprintln(w)
}

// outputApolloJSONL writes one JSON object per discovered person.
// encoding/json already escapes control characters, so no sanitization needed.
// Preview (un-revealed) people omit email/email_status via omitempty so a
// consumer never misreads a blank email as confirmed-absent.
func outputApolloJSONL(w io.Writer, result *apollo.DomainResult) {
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

// personName returns the sanitized display name, preferring Apollo's full Name
// and falling back to "First Last".
func personName(p *apollo.Person) string {
	if p.Name != "" {
		return sanitizeTerminal(p.Name)
	}
	return strings.TrimSpace(sanitizeTerminal(p.FirstName) + " " + sanitizeTerminal(p.LastName))
}
