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
			Department:         getField(record, colIndex, "department"),
			Seniority:          getField(record, colIndex, "seniority"),
			Location:           coalesce(getField(record, colIndex, "location"), getField(record, colIndex, "region")),
			LinkedinURL:        coalesce(getField(record, colIndex, "linkedinprofileurl"), getField(record, colIndex, "profileurl")),
			SalesNavURL:        getField(record, colIndex, "salesnavigatorurl"),
			Headline:           getField(record, colIndex, "headline"),
			ImageURL:           getField(record, colIndex, "imgurl"),
			ConnectionDegree:   getField(record, colIndex, "connectiondegree"),
			Sources:            []string{"linkedin-salesnav"},
			VerificationStatus: "unverified",
		}

		if p.Department == "" || p.Seniority == "" {
			dept, sen := inferDeptSeniority(p.Title, p.Headline)
			if p.Department == "" {
				p.Department = dept
			}
			if p.Seniority == "" {
				p.Seniority = sen
			}
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

var seniorityKeywords = []struct {
	keyword   string
	seniority string
}{
	{"chief", "c-suite"},
	{"ceo", "c-suite"},
	{"cto", "c-suite"},
	{"cfo", "c-suite"},
	{"coo", "c-suite"},
	{"ciso", "c-suite"},
	{"cio", "c-suite"},
	{"cmo", "c-suite"},
	{"cpo", "c-suite"},
	{"cro", "c-suite"},
	{"partner", "partner"},
	{"founder", "founder"},
	{"co-founder", "founder"},
	{"cofounder", "founder"},
	{"owner", "owner"},
	{"president", "vp"},
	{"vice president", "vp"},
	{"vp ", "vp"},
	{"svp", "vp"},
	{"evp", "vp"},
	{"avp", "vp"},
	{"head of", "director"},
	{"director", "director"},
	{"senior manager", "senior"},
	{"sr. manager", "senior"},
	{"sr manager", "senior"},
	{"manager", "manager"},
	{"principal", "senior"},
	{"staff", "senior"},
	{"senior", "senior"},
	{"sr.", "senior"},
	{"sr ", "senior"},
	{"lead", "senior"},
	{"junior", "entry"},
	{"jr.", "entry"},
	{"jr ", "entry"},
	{"intern", "training"},
	{"associate", "entry"},
	{"analyst", "entry"},
}

var departmentKeywords = []struct {
	keyword    string
	department string
}{
	{"information security", "security"},
	{"infosec", "security"},
	{"cybersecurity", "security"},
	{"cyber security", "security"},
	{"security", "security"},
	{"information technology", "it"},
	{"software engineer", "engineering"},
	{"software develop", "engineering"},
	{"engineering", "engineering"},
	{"devops", "engineering"},
	{"sre", "engineering"},
	{"platform", "engineering"},
	{"infrastructure", "engineering"},
	{"data scien", "data"},
	{"data engineer", "data"},
	{"machine learning", "data"},
	{"analytics", "data"},
	{"product manag", "product"},
	{"product design", "product"},
	{"product", "product"},
	{"design", "design"},
	{"ux", "design"},
	{"ui", "design"},
	{"marketing", "marketing"},
	{"growth", "marketing"},
	{"brand", "marketing"},
	{"communications", "marketing"},
	{"sales", "sales"},
	{"account executive", "sales"},
	{"business develop", "sales"},
	{"customer success", "customer_success"},
	{"support", "support"},
	{"human resource", "hr"},
	{"people ops", "hr"},
	{"talent", "hr"},
	{"recruiting", "hr"},
	{"finance", "finance"},
	{"accounting", "finance"},
	{"legal", "legal"},
	{"compliance", "legal"},
	{"operations", "operations"},
	{"supply chain", "operations"},
	{"logistics", "operations"},
	{"research", "research"},
	{"r&d", "research"},
}

// inferDeptSeniority attempts best-effort extraction of department and
// seniority from a LinkedIn title or headline. Returns empty strings when
// no keywords match — callers should treat empty as "unknown".
func inferDeptSeniority(title, headline string) (department, seniority string) {
	combined := strings.ToLower(title + " " + headline)

	for _, s := range seniorityKeywords {
		if strings.Contains(combined, s.keyword) {
			seniority = s.seniority
			break
		}
	}

	for _, d := range departmentKeywords {
		if strings.Contains(combined, d.keyword) {
			department = d.department
			break
		}
	}

	return department, seniority
}
