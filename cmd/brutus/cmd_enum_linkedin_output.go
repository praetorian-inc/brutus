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

	pb "github.com/praetorian-inc/brutus/pkg/enum/phantombuster"
)

func outputLinkedinHuman(w io.Writer, result *pb.ScrapeResult, useColor bool) {
	_, _ = fmt.Fprintf(w, "\n%s %s\n", dim(useColor, SymbolInfo),
		heading(useColor, "LinkedIn Sales Navigator"))
	_, _ = fmt.Fprintf(w, "  Profiles scraped: %d\n", result.Total)

	if len(result.Profiles) == 0 {
		_, _ = fmt.Fprintf(w, "\n  %s No profiles found\n", dim(useColor, SymbolInfo))
		_, _ = fmt.Fprintln(w)
		return
	}

	_, _ = fmt.Fprintf(w, "\n  %s%-24s %-24s %-16s %-20s %-40s%s\n",
		colorIf(useColor, ColorBold),
		"Name", "Title", "Dept", "Company", "LinkedIn",
		colorIf(useColor, ColorReset))

	for i := range result.Profiles {
		p := &result.Profiles[i]
		name := sanitizeTerminal(p.FullName)
		if name == "" {
			name = sanitizeTerminal(p.FirstName + " " + p.LastName)
		}
		_, _ = fmt.Fprintf(w, "  %-24s %-24s %-16s %-20s %s%-40s%s\n",
			truncate(name, 24),
			truncate(sanitizeTerminal(p.Title), 24),
			truncate(sanitizeTerminal(p.Department), 16),
			truncate(sanitizeTerminal(p.Company), 20),
			colorIf(useColor, ColorCyan),
			truncate(sanitizeTerminal(p.LinkedinURL), 40),
			colorIf(useColor, ColorReset))
	}
	_, _ = fmt.Fprintln(w)
}

func outputLinkedinJSONL(w io.Writer, result *pb.ScrapeResult) {
	type linkedinJSON struct {
		Type               string   `json:"type"`
		FirstName          string   `json:"first_name,omitempty"`
		LastName           string   `json:"last_name,omitempty"`
		FullName           string   `json:"full_name,omitempty"`
		Title              string   `json:"title,omitempty"`
		Company            string   `json:"company,omitempty"`
		CompanyURL         string   `json:"company_url,omitempty"`
		Department         string   `json:"department,omitempty"`
		Seniority          string   `json:"seniority,omitempty"`
		Location           string   `json:"location,omitempty"`
		LinkedinURL        string   `json:"linkedin_url,omitempty"`
		SalesNavURL        string   `json:"sales_nav_url,omitempty"`
		Headline           string   `json:"headline,omitempty"`
		ConnectionDegree   string   `json:"connection_degree,omitempty"`
		Sources            []string `json:"sources"`
		VerificationStatus string   `json:"verification_status"`
	}

	enc := json.NewEncoder(w)
	for i := range result.Profiles {
		p := &result.Profiles[i]
		jr := linkedinJSON{
			Type:               "linkedin",
			FirstName:          p.FirstName,
			LastName:           p.LastName,
			FullName:           p.FullName,
			Title:              p.Title,
			Company:            p.Company,
			CompanyURL:         p.CompanyURL,
			Department:         p.Department,
			Seniority:          p.Seniority,
			Location:           p.Location,
			LinkedinURL:        p.LinkedinURL,
			SalesNavURL:        p.SalesNavURL,
			Headline:           p.Headline,
			ConnectionDegree:   p.ConnectionDegree,
			Sources:            p.Sources,
			VerificationStatus: p.VerificationStatus,
		}
		if err := enc.Encode(jr); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding linkedin JSON: %v\n", err)
		}
	}
}
