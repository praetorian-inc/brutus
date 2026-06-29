// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apollo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// fixedNow is a stable "current time" used by all computeTenure tests so that
// expected month counts are deterministic regardless of when the suite runs.
var fixedNow = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// computeTenure: table-driven tests with a fixed "now"
// ---------------------------------------------------------------------------

func TestComputeTenure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		employment []EmploymentEntry
		wantAvail  bool
		wantCurr   bool
		wantMonths int
		wantPrec   string
		wantSrc    string
		wantReason string
	}{
		{
			name: "current role with day-precision StartDate",
			// Start 2021-06-01 → fixedNow 2024-06-01 = 36 months exactly.
			employment: []EmploymentEntry{
				{Organization: "ACME", Title: "Engineer", StartDate: "2021-06-01", Current: true},
			},
			wantAvail:  true,
			wantCurr:   true,
			wantMonths: 36,
			wantPrec:   "day",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "year-only StartDate — precision is year",
			// Start 2020 (Jan 1) → fixedNow 2024-06-01 = 53 months.
			employment: []EmploymentEntry{
				{Organization: "ACME", Title: "Engineer", StartDate: "2020", Current: true},
			},
			wantAvail:  true,
			wantCurr:   true,
			wantMonths: 53,
			wantPrec:   "year",
			wantSrc:    "apollo:employment_history",
		},
		{
			name:       "empty employment slice — unavailable",
			employment: []EmploymentEntry{},
			wantAvail:  false,
			wantReason: "employment history not revealed",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "no entry with Current==true — unavailable",
			employment: []EmploymentEntry{
				{Organization: "Old Corp", Title: "Analyst", StartDate: "2018-01", Current: false},
				{Organization: "Another Co", Title: "Senior", StartDate: "2015-06-01", Current: false},
			},
			wantAvail:  false,
			wantReason: "no current role with dates",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "current role with empty StartDate — unavailable",
			employment: []EmploymentEntry{
				{Organization: "ACME", Title: "Engineer", StartDate: "", Current: true},
			},
			wantAvail:  false,
			wantReason: "current role has no start date",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "current role with unparseable StartDate — unavailable",
			employment: []EmploymentEntry{
				{Organization: "ACME", Title: "Engineer", StartDate: "not-a-date", Current: true},
			},
			wantAvail:  false,
			wantReason: "current role has no start date",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "multiple current entries — picks latest parseable StartDate",
			// earliest: 2019-01, latest: 2022-03-15 → fixedNow 2024-06-01 = 26 months
			employment: []EmploymentEntry{
				{Organization: "Early Corp", Title: "A", StartDate: "2019-01", Current: true},
				{Organization: "Latest Corp", Title: "B", StartDate: "2022-03-15", Current: true},
				{Organization: "Mid Corp", Title: "C", StartDate: "2021-06", Current: true},
			},
			wantAvail:  true,
			wantCurr:   true,
			wantMonths: 26,
			wantPrec:   "day",
			wantSrc:    "apollo:employment_history",
		},
		{
			name: "month-precision StartDate",
			// Start 2022-06 (June 1) → fixedNow 2024-06-01 = 24 months.
			employment: []EmploymentEntry{
				{Organization: "ACME", Title: "Engineer", StartDate: "2022-06", Current: true},
			},
			wantAvail:  true,
			wantCurr:   true,
			wantMonths: 24,
			wantPrec:   "month",
			wantSrc:    "apollo:employment_history",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := computeTenure(tc.employment, fixedNow)

			require.Equal(t, tc.wantAvail, got.Available, "Available mismatch")
			assert.Equal(t, tc.wantSrc, got.Source, "Source must always be apollo:employment_history")

			if !tc.wantAvail {
				assert.Equal(t, tc.wantReason, got.Reason, "Reason mismatch for unavailable tenure")
				assert.Equal(t, 0, got.Months, "Months must be zero for unavailable tenure")
				return
			}

			assert.True(t, got.Current, "Current must be true for available tenure")
			assert.Equal(t, tc.wantMonths, got.Months, "Months mismatch")
			assert.Equal(t, tc.wantPrec, got.Precision, "Precision mismatch")
			assert.Empty(t, got.Reason, "Reason must be empty for available tenure")
		})
	}
}

// TestComputeTenure_MultipleCurrentNilStart verifies that when one Current entry
// has an unparseable StartDate and another has a parseable one, we select the
// parseable entry (not the nil-start one). This exercises the case==nil branch
// inside the "later parseable" pick logic.
func TestComputeTenure_MultipleCurrentFirstUnparseable(t *testing.T) {
	t.Parallel()
	employment := []EmploymentEntry{
		{Organization: "Bad Corp", Title: "X", StartDate: "???", Current: true},
		{Organization: "Good Corp", Title: "Y", StartDate: "2023-01-01", Current: true},
	}
	// 2023-01-01 → fixedNow 2024-06-01 = 17 months
	got := computeTenure(employment, fixedNow)
	require.True(t, got.Available)
	assert.Equal(t, 17, got.Months)
	assert.Equal(t, "day", got.Precision)
}

// TestToPerson_TenurePopulated verifies that toPerson correctly populates Tenure
// from an apolloPerson that has employment_history with a current role. This is
// the integration point: computeTenure is called inside toPerson.
func TestToPerson_TenurePopulated(t *testing.T) {
	t.Parallel()
	src := apolloPerson{
		ID:        "p1",
		FirstName: "Alice",
		LastName:  "Smith",
		EmploymentHistory: []apolloEmploymentEntry{
			{
				OrganizationName: "ACME",
				Title:            "Engineer",
				StartDate:        "2021-01-15",
				Current:          true,
			},
		},
	}
	got := src.toPerson()

	// Tenure must be available and current (time.Now is used inside toPerson, so
	// we only assert the structural invariants, not the exact month count).
	require.True(t, got.Tenure.Available, "Tenure must be available when current role has start date")
	assert.True(t, got.Tenure.Current)
	assert.Equal(t, "apollo:employment_history", got.Tenure.Source)
	assert.Equal(t, "day", got.Tenure.Precision)
	assert.Greater(t, got.Tenure.Months, 0, "Months must be positive (start date is in the past)")
}

// TestToPerson_TenureUnavailableNoHistory verifies that toPerson returns an
// unavailable tenure when the person has no employment history (pre-reveal thin
// record from the search tier).
func TestToPerson_TenureUnavailableNoHistory(t *testing.T) {
	t.Parallel()
	src := apolloPerson{
		ID:        "p2",
		FirstName: "Bob",
		LastName:  "Jones",
		// EmploymentHistory is nil/empty — pre-reveal discovery record.
	}
	got := src.toPerson()

	assert.False(t, got.Tenure.Available, "pre-reveal person must have unavailable tenure")
	assert.Equal(t, "apollo:employment_history", got.Tenure.Source)
	assert.NotEmpty(t, got.Tenure.Reason)
	assert.Equal(t, 0, got.Tenure.Months)
}

// TestMergeReveal_TenureCarriedOver verifies that mergeReveal copies the tenure
// from the enriched record onto the discovered person, ensuring that after
// RevealEmails the discovered person carries the tenure from enrichment.
func TestMergeReveal_TenureCarriedOver(t *testing.T) {
	t.Parallel()
	discovered := Person{ID: "p1", FirstName: "Alice"}
	enriched := Person{
		ID: "p1",
		Tenure: enum.Tenure{
			Available: true,
			Months:    18,
			Current:   true,
			Source:    "apollo:employment_history",
			Precision: "month",
		},
	}
	mergeReveal(&discovered, enriched)
	assert.Equal(t, enriched.Tenure, discovered.Tenure, "mergeReveal must copy tenure from enriched person")
}
