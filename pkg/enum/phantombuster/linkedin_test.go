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
	"testing"
)

func TestParseSalesNavCSV_BasicFields(t *testing.T) {
	csv := `fullName,firstName,lastName,jobTitle,companyName,location,linkedinProfileUrl,salesNavigatorUrl,headline
Jane Doe,Jane,Doe,VP Engineering,Acme Corp,San Francisco,https://linkedin.com/in/janedoe,https://salesnavigator.linkedin.com/in/janedoe,VP Engineering at Acme
John Smith,John,Smith,CTO,Widgets Inc,New York,https://linkedin.com/in/johnsmith,,CTO at Widgets
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 profiles, got %d", result.Total)
	}

	p := result.Profiles[0]
	if p.FirstName != "Jane" || p.LastName != "Doe" {
		t.Errorf("unexpected name: %q %q", p.FirstName, p.LastName)
	}
	if p.Title != "VP Engineering" {
		t.Errorf("expected title VP Engineering, got %q", p.Title)
	}
	if p.Company != "Acme Corp" {
		t.Errorf("expected company Acme Corp, got %q", p.Company)
	}
	if p.LinkedinURL != "https://linkedin.com/in/janedoe" {
		t.Errorf("unexpected LinkedIn URL: %q", p.LinkedinURL)
	}
	if p.Location != "San Francisco" {
		t.Errorf("unexpected location: %q", p.Location)
	}
	if p.SalesNavURL != "https://salesnavigator.linkedin.com/in/janedoe" {
		t.Errorf("unexpected Sales Nav URL: %q", p.SalesNavURL)
	}

	// Verification-ready fields.
	if len(p.Sources) != 1 || p.Sources[0] != "linkedin-salesnav" {
		t.Errorf("expected sources [linkedin-salesnav], got %v", p.Sources)
	}
	if p.VerificationStatus != "unverified" {
		t.Errorf("expected verificationStatus unverified, got %q", p.VerificationStatus)
	}
}

func TestParseSalesNavCSV_AlternateColumnNames(t *testing.T) {
	csv := `fullName,firstName,lastName,job,company,region,profileUrl
Alice Lee,Alice,Lee,Manager,BigCo,London,https://linkedin.com/in/alicelee
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 profile, got %d", result.Total)
	}

	p := result.Profiles[0]
	if p.Title != "Manager" {
		t.Errorf("expected title Manager (from 'job' column), got %q", p.Title)
	}
	if p.Company != "BigCo" {
		t.Errorf("expected company BigCo (from 'company' column), got %q", p.Company)
	}
	if p.Location != "London" {
		t.Errorf("expected location London (from 'region' column), got %q", p.Location)
	}
	if p.LinkedinURL != "https://linkedin.com/in/alicelee" {
		t.Errorf("expected LinkedIn URL from 'profileUrl', got %q", p.LinkedinURL)
	}
}

func TestParseSalesNavCSV_FullNameFallback(t *testing.T) {
	csv := `firstName,lastName,jobTitle,companyName,linkedinProfileUrl
Bob,Jones,Engineer,StartupXYZ,https://linkedin.com/in/bobjones
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	p := result.Profiles[0]
	if p.FullName != "Bob Jones" {
		t.Errorf("expected fullName fallback 'Bob Jones', got %q", p.FullName)
	}
}

func TestParseSalesNavCSV_Empty(t *testing.T) {
	csv := `fullName,firstName,lastName,jobTitle,companyName
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected 0 profiles, got %d", result.Total)
	}
}

func TestParseSalesNavCSV_MissingColumns(t *testing.T) {
	csv := `firstName,lastName
Charlie,Brown
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 profile, got %d", result.Total)
	}
	p := result.Profiles[0]
	if p.Title != "" {
		t.Errorf("expected empty title for missing column, got %q", p.Title)
	}
	if p.Company != "" {
		t.Errorf("expected empty company for missing column, got %q", p.Company)
	}
}

func TestParseSalesNavCSV_NoHeaders(t *testing.T) {
	_, err := ParseSalesNavCSV([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty CSV")
	}
}

func TestParseSalesNavCSV_QuotedFields(t *testing.T) {
	csv := `fullName,firstName,lastName,jobTitle,companyName,headline
"O'Brien, Pat",Pat,O'Brien,"Sr. Director, Engineering","Acme, Inc.","Director at Acme, Inc."
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	p := result.Profiles[0]
	if p.FullName != "O'Brien, Pat" {
		t.Errorf("unexpected fullName: %q", p.FullName)
	}
	if p.Title != "Sr. Director, Engineering" {
		t.Errorf("unexpected title: %q", p.Title)
	}
	if p.Company != "Acme, Inc." {
		t.Errorf("unexpected company: %q", p.Company)
	}
}

func TestParseSalesNavCSV_DeptSeniorityFromCSV(t *testing.T) {
	csv := `fullName,firstName,lastName,jobTitle,department,seniority,companyName
Jane Doe,Jane,Doe,VP Engineering,Engineering,VP,Acme Corp
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	p := result.Profiles[0]
	if p.Department != "Engineering" {
		t.Errorf("expected department Engineering from CSV column, got %q", p.Department)
	}
	if p.Seniority != "VP" {
		t.Errorf("expected seniority VP from CSV column, got %q", p.Seniority)
	}
}

func TestParseSalesNavCSV_DeptSeniorityInferred(t *testing.T) {
	csv := `fullName,firstName,lastName,jobTitle,companyName,headline
Jane Doe,Jane,Doe,VP Engineering,Acme Corp,VP Engineering at Acme
John Smith,John,Smith,CTO,Widgets Inc,CTO at Widgets
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}

	p0 := result.Profiles[0]
	if p0.Seniority != "vp" {
		t.Errorf("expected inferred seniority 'vp' for VP Engineering, got %q", p0.Seniority)
	}
	if p0.Department != "engineering" {
		t.Errorf("expected inferred department 'engineering' for VP Engineering, got %q", p0.Department)
	}

	p1 := result.Profiles[1]
	if p1.Seniority != "c-suite" {
		t.Errorf("expected inferred seniority 'c-suite' for CTO, got %q", p1.Seniority)
	}
}

func TestParseSalesNavCSV_CSVOverridesInference(t *testing.T) {
	csv := `fullName,jobTitle,department,seniority,headline
Jane Doe,VP Engineering,Ops,Executive,VP Engineering at Acme
`
	result, err := ParseSalesNavCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseSalesNavCSV: %v", err)
	}
	p := result.Profiles[0]
	if p.Department != "Ops" {
		t.Errorf("CSV-provided department should take priority, got %q", p.Department)
	}
	if p.Seniority != "Executive" {
		t.Errorf("CSV-provided seniority should take priority, got %q", p.Seniority)
	}
}

func TestInferDeptSeniority(t *testing.T) {
	tests := []struct {
		title    string
		headline string
		wantDept string
		wantSen  string
	}{
		{"VP Engineering", "", "engineering", "vp"},
		{"CTO", "CTO at Acme", "", "c-suite"},
		{"Senior Security Engineer", "", "security", "senior"},
		{"Junior Analyst", "", "", "entry"},
		{"Marketing Manager", "", "marketing", "manager"},
		{"Co-Founder & CEO", "", "", "c-suite"},
		{"", "Head of Product at Widgets", "product", "director"},
		{"Intern", "Summer Engineering Intern", "engineering", "training"},
		{"", "", "", ""},
		{"Account Executive", "Account Executive at BigCo", "sales", ""},
		{"Principal Data Scientist", "", "data", "senior"},
		{"Staff Software Engineer", "Platform Engineering", "engineering", "senior"},
		{"CISO", "Chief Information Security Officer", "security", "c-suite"},
	}

	for _, tc := range tests {
		t.Run(tc.title+"/"+tc.headline, func(t *testing.T) {
			dept, sen := inferDeptSeniority(tc.title, tc.headline)
			if dept != tc.wantDept {
				t.Errorf("department: got %q, want %q", dept, tc.wantDept)
			}
			if sen != tc.wantSen {
				t.Errorf("seniority: got %q, want %q", sen, tc.wantSen)
			}
		})
	}
}
