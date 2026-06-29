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

package lusha

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tenure: Lusha always returns unavailable (no employment dates in source)
// ---------------------------------------------------------------------------

// TestToContact_TenureUnavailable verifies that a contact built from a Lusha
// v3 enrich result always carries an unavailable tenure — the source provides
// no employment start/end dates so no derivation is possible (no fabrication).
func TestToContact_TenureUnavailable(t *testing.T) {
	t.Parallel()
	r := lushaResult{}
	r.FirstName = "Alice"
	r.LastName = "Smith"
	r.JobTitle.Title = "Engineer"
	r.Company.Name = "ACME"
	r.Company.Domain = "acme.com"

	resp := &lushaEnrichResponse{
		Results: []lushaResult{r},
	}
	got := toContact(resp)

	assert.False(t, got.Tenure.Available, "Lusha tenure must always be unavailable (no employment dates)")
	assert.Equal(t, "lusha", got.Tenure.Source, "Source must be 'lusha'")
	assert.Equal(t, "no employment dates from source", got.Tenure.Reason,
		"Reason must explain why tenure is unavailable")
	assert.Equal(t, 0, got.Tenure.Months, "Months must be zero for unavailable tenure")
	assert.False(t, got.Tenure.Current, "Current must be false for unavailable tenure")
	assert.Empty(t, got.Tenure.Precision, "Precision must be empty for unavailable tenure")
}

// TestToProspectContact_TenureUnavailable verifies that the prospect-search code
// path (toProspectContact) also returns an unavailable tenure with the same
// provenance as the enrich path.
func TestToProspectContact_TenureUnavailable(t *testing.T) {
	t.Parallel()
	d := &prospectEnrichData{
		FullName:    "Bob Jones",
		JobTitle:    "Manager",
		CompanyName: "SomeCorp",
	}

	got := toProspectContact(d)

	assert.False(t, got.Tenure.Available, "prospect contact tenure must always be unavailable")
	assert.Equal(t, "lusha", got.Tenure.Source)
	assert.Equal(t, "no employment dates from source", got.Tenure.Reason)
	assert.Equal(t, 0, got.Tenure.Months)
}
