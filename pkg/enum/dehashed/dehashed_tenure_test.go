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

package dehashed

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Tenure: DeHashed always returns unavailable (breach data, no employment dates)
// ---------------------------------------------------------------------------

const (
	dehashedTenureSource = "dehashed"
	dehashedTenureReason = "breach data, no employment dates"
)

// TestToRecord_TenureUnavailable verifies that a Record built from a raw API
// entry always carries an unavailable tenure with the correct source/reason.
// Breach data carries no employment dates so no derivation is possible.
func TestToRecord_TenureUnavailable(t *testing.T) {
	t.Parallel()
	entry := &apiEntry{
		ID:       "rec-1",
		Email:    []string{"alice@example.com"},
		Database: "breach-db",
	}
	got := toRecord(entry)

	assert.False(t, got.Tenure.Available, "Record tenure must always be unavailable for DeHashed")
	assert.Equal(t, dehashedTenureSource, got.Tenure.Source)
	assert.Equal(t, dehashedTenureReason, got.Tenure.Reason)
	assert.Equal(t, 0, got.Tenure.Months)
	assert.False(t, got.Tenure.Current)
	assert.Empty(t, got.Tenure.Precision)
}

// TestRefine_TenureUnavailableOnEntry verifies that the Refine pipeline
// propagates unavailable tenure onto each Entry. This covers the no-dedup path
// (one Entry per surviving record).
func TestRefine_TenureUnavailableOnEntry(t *testing.T) {
	t.Parallel()
	records := []Record{
		{
			Email:    []string{"alice@example.com"},
			Database: "breach-db",
			Tenure:   unavailableTenure(),
		},
		{
			Email:    []string{"bob@example.com"},
			Database: "breach-db2",
			Tenure:   unavailableTenure(),
		},
	}
	entries := Refine(records, RefineOptions{})
	require.Len(t, entries, 2)

	for _, e := range entries {
		assert.False(t, e.Tenure.Available, "Entry tenure must always be unavailable")
		assert.Equal(t, dehashedTenureSource, e.Tenure.Source)
		assert.Equal(t, dehashedTenureReason, e.Tenure.Reason)
		assert.Equal(t, 0, e.Tenure.Months)
	}
}

// TestRefine_TenureUnavailableWithDedup verifies that the dedup/merge path also
// results in an unavailable tenure on the merged Entry. Multiple records for the
// same email are merged into a single Entry; tenure must remain unavailable.
func TestRefine_TenureUnavailableWithDedup(t *testing.T) {
	t.Parallel()
	records := []Record{
		{
			Email:     []string{"alice@example.com"},
			Database:  "breach-a",
			Passwords: []string{"pass1"},
			Tenure:    unavailableTenure(),
		},
		{
			Email:     []string{"alice@example.com"},
			Database:  "breach-b",
			Passwords: []string{"pass2"},
			Tenure:    unavailableTenure(),
		},
	}
	entries := Refine(records, RefineOptions{Dedup: true})
	require.Len(t, entries, 1, "dedup must merge two records for the same email into one Entry")

	e := entries[0]
	assert.Equal(t, "alice@example.com", e.Email)
	assert.Equal(t, 2, e.Count, "merged Entry must count both records")

	// Tenure must remain unavailable even after merging.
	assert.False(t, e.Tenure.Available, "merged Entry tenure must be unavailable")
	assert.Equal(t, dehashedTenureSource, e.Tenure.Source)
	assert.Equal(t, dehashedTenureReason, e.Tenure.Reason)
}
