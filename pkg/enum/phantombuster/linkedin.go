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

package phantombuster

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// Profile is a single person scraped from LinkedIn Sales Navigator. Fields
// align with the PhantomBuster Sales Navigator Profile Scraper output.
// Verification-ready fields (Sources, VerificationStatus, Confidence) are
// reserved per 10T-373 so confirmation oracles bolt on with no migration.
type Profile struct {
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	FullName         string `json:"fullName"`
	Title            string `json:"title"`
	Company          string `json:"company"`
	CompanyURL       string `json:"companyUrl,omitempty"`
	Department       string `json:"department,omitempty"`
	Seniority        string `json:"seniority,omitempty"`
	Location         string `json:"location,omitempty"`
	LinkedinURL      string `json:"linkedinUrl"`
	SalesNavURL      string `json:"salesNavUrl,omitempty"`
	Headline         string `json:"headline,omitempty"`
	ImageURL         string `json:"imageUrl,omitempty"`
	ConnectionDegree string `json:"connectionDegree,omitempty"`

	// Verification-ready fields (10T-373). Zero-value until confirmation
	// oracles run; included now to avoid schema migration.
	Sources            []string `json:"sources"`
	VerificationStatus string   `json:"verificationStatus"`
	Confidence         float64  `json:"confidence"`

	Error error `json:"-"`
}

// ScrapeResult aggregates the parsed output from a LinkedIn Sales Navigator
// scrape run.
type ScrapeResult struct {
	Profiles []Profile `json:"profiles"`
	Total    int       `json:"total"`
	AgentID  string    `json:"agentId"`
}

// ParseSalesNavCSV parses the CSV output from a PhantomBuster Sales Navigator
// Profile Scraper run. The parser is lenient: missing columns map to empty
// strings. PhantomBuster does not publish a formal CSV schema, so column
// names are mapped best-effort from documented and observed field names.
func ParseSalesNavCSV(data []byte) (*ScrapeResult, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV headers: %w", err)
	}

	colIndex := make(map[string]int, len(headers))
	for i, h := range headers {
		colIndex[strings.TrimSpace(strings.ToLower(h))] = i
	}

	var profiles []Profile
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading CSV row: %w", err)
		}

		p := Profile{
			FirstName:          getField(record, colIndex, "firstname"),
			LastName:           getField(record, colIndex, "lastname"),
			FullName:           getField(record, colIndex, "fullname"),
			Title:              coalesce(getField(record, colIndex, "jobtitle"), getField(record, colIndex, "job"), getField(record, colIndex, "title")),
			Company:            coalesce(getField(record, colIndex, "companyname"), getField(record, colIndex, "company")),
			CompanyURL:         coalesce(getField(record, colIndex, "companylinkedinurl"), getField(record, colIndex, "companyurl")),
			Location:           coalesce(getField(record, colIndex, "location"), getField(record, colIndex, "region")),
			LinkedinURL:        coalesce(getField(record, colIndex, "linkedinprofileurl"), getField(record, colIndex, "profileurl")),
			SalesNavURL:        getField(record, colIndex, "salesnavigatorurl"),
			Headline:           getField(record, colIndex, "headline"),
			ImageURL:           getField(record, colIndex, "imgurl"),
			ConnectionDegree:   getField(record, colIndex, "connectiondegree"),
			Sources:            []string{"linkedin-salesnav"},
			VerificationStatus: "unverified",
		}

		if p.FullName == "" && p.FirstName != "" {
			p.FullName = strings.TrimSpace(p.FirstName + " " + p.LastName)
		}

		profiles = append(profiles, p)
	}

	return &ScrapeResult{
		Profiles: profiles,
		Total:    len(profiles),
	}, nil
}

// getField safely retrieves a field from a CSV record by column name.
func getField(record []string, colIndex map[string]int, name string) string {
	idx, ok := colIndex[name]
	if !ok || idx >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[idx])
}

// coalesce returns the first non-empty string from the arguments.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
