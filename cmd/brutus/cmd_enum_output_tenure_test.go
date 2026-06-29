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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/apollo"
	"github.com/praetorian-inc/brutus/pkg/enum/dehashed"
	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
	"github.com/praetorian-inc/brutus/pkg/enum/lusha"
)

// ---------------------------------------------------------------------------
// Apollo: tenure in both human and JSONL output
// ---------------------------------------------------------------------------

// TestOutputApolloHuman_TenureAvailable verifies that the enriched human output
// includes the tenure string rendered by Tenure.String() for a person with an
// available current tenure.
func TestOutputApolloHuman_TenureAvailable(t *testing.T) {
	result := &apollo.DomainResult{
		Domain:   "example.com",
		Revealed: true,
		People: []apollo.Person{
			{
				ID:       "p1",
				Name:     "Alice Smith",
				Email:    "alice@example.com",
				Revealed: true,
				Tenure: enum.Tenure{
					Available: true,
					Months:    38, // 3y 2m
					Current:   true,
					Source:    "apollo:employment_history",
					Precision: "day",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputApolloHuman(&buf, result, false)
	out := buf.String()

	assert.Contains(t, out, "Tenure", "human output must include a Tenure column header")
	assert.Contains(t, out, "3y 2m (current)", "human output must include the rendered tenure string")
}

// TestOutputApolloHuman_TenureUnavailable verifies that the discovery-mode human
// output does NOT render a Tenure column (tenure is only shown in enriched mode).
func TestOutputApolloHuman_TenureUnavailable(t *testing.T) {
	result := &apollo.DomainResult{
		Domain:   "example.com",
		Revealed: false,
		People: []apollo.Person{
			{
				ID:   "p1",
				Name: "Alice Smith",
				Tenure: enum.Tenure{
					Available: false,
					Source:    "apollo:employment_history",
					Reason:    "employment history not revealed",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputApolloHuman(&buf, result, false)
	out := buf.String()

	// In discovery mode the Tenure column is not rendered (no enrichment happened).
	assert.NotContains(t, out, "Tenure", "discovery-mode output must not include Tenure column")
}

// TestOutputApolloJSONL_TenureAvailable verifies that the enriched JSONL output
// includes a "tenure" key with available=true and the correct fields for a
// person with a derivable current role.
func TestOutputApolloJSONL_TenureAvailable(t *testing.T) {
	result := &apollo.DomainResult{
		Domain:   "example.com",
		Revealed: true,
		People: []apollo.Person{
			{
				ID:       "p1",
				Name:     "Alice Smith",
				Email:    "alice@example.com",
				Revealed: true,
				Tenure: enum.Tenure{
					Available: true,
					Months:    24,
					Current:   true,
					Source:    "apollo:employment_history",
					Precision: "month",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputApolloJSONL(&buf, result)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

	tenureRaw, hasTenure := obj["tenure"]
	require.True(t, hasTenure, "enriched JSONL must include a 'tenure' key")

	tenureMap, ok := tenureRaw.(map[string]interface{})
	require.True(t, ok, "tenure must be a JSON object")

	assert.Equal(t, true, tenureMap["available"], "tenure.available must be true")
	assert.Equal(t, float64(24), tenureMap["months"], "tenure.months must match")
	assert.Equal(t, true, tenureMap["current"], "tenure.current must be true")
	assert.Equal(t, "apollo:employment_history", tenureMap["source"])
	assert.Equal(t, "month", tenureMap["precision"])
}

// TestOutputApolloJSONL_TenureUnavailable verifies that the enriched JSONL
// output for a person with no derivable tenure carries available=false and the
// correct reason string.
func TestOutputApolloJSONL_TenureUnavailable(t *testing.T) {
	result := &apollo.DomainResult{
		Domain:   "example.com",
		Revealed: true,
		People: []apollo.Person{
			{
				ID:       "p1",
				Name:     "Alice Smith",
				Email:    "alice@example.com",
				Revealed: true,
				Tenure: enum.Tenure{
					Available: false,
					Source:    "apollo:employment_history",
					Reason:    "employment history not revealed",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputApolloJSONL(&buf, result)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))

	tenureMap, ok := obj["tenure"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, tenureMap["available"])
	assert.Equal(t, "apollo:employment_history", tenureMap["source"])
	assert.Equal(t, "employment history not revealed", tenureMap["reason"])
}

// ---------------------------------------------------------------------------
// Lusha: tenure in both human and JSONL output
// ---------------------------------------------------------------------------

// TestOutputLushaHuman_TenureUnavailable verifies that the Lusha human output
// includes the tenure line with the unavailable rendering.
func TestOutputLushaHuman_TenureUnavailable(t *testing.T) {
	c := &lusha.Contact{
		Name:    "Bob Jones",
		Company: "ACME",
		Tenure: enum.Tenure{
			Available: false,
			Source:    "lusha",
			Reason:    "no employment dates from source",
		},
	}
	var buf bytes.Buffer
	outputLushaHuman(&buf, c, false)
	out := buf.String()

	assert.Contains(t, out, "Tenure:", "human output must include Tenure: line")
	assert.Contains(t, out, "unavailable — no employment dates from source",
		"Lusha human output must render the unavailable reason")
}

// TestOutputLushaJSONL_TenureUnavailable verifies that Lusha JSONL includes a
// "tenure" key with available=false and the correct lusha source/reason.
func TestOutputLushaJSONL_TenureUnavailable(t *testing.T) {
	c := &lusha.Contact{
		Name: "Bob Jones",
		Tenure: enum.Tenure{
			Available: false,
			Source:    "lusha",
			Reason:    "no employment dates from source",
		},
	}
	var buf bytes.Buffer
	outputLushaJSONL(&buf, c)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))

	tenureMap, ok := obj["tenure"].(map[string]interface{})
	require.True(t, ok, "lusha JSONL must include a 'tenure' object")
	assert.Equal(t, false, tenureMap["available"])
	assert.Equal(t, "lusha", tenureMap["source"])
	assert.Equal(t, "no employment dates from source", tenureMap["reason"])
}

// ---------------------------------------------------------------------------
// DeHashed: tenure in both human and JSONL output
// ---------------------------------------------------------------------------

// TestOutputDehashedHuman_TenureUnavailable verifies that the DeHashed human
// output renders the tenure column with the unavailable string.
func TestOutputDehashedHuman_TenureUnavailable(t *testing.T) {
	entries := []dehashed.Entry{
		{
			Email:     "carol@example.com",
			Databases: []string{"breach-db"},
			Count:     1,
			Tenure: enum.Tenure{
				Available: false,
				Source:    "dehashed",
				Reason:    "breach data, no employment dates",
			},
		},
	}
	var buf bytes.Buffer
	outputDehashedHuman(&buf, "example.com", 1, 1, 0, entries, false, false)
	out := buf.String()

	assert.Contains(t, out, "Tenure", "dehashed human output must include Tenure column header")
	assert.Contains(t, out, "unavailable", "dehashed human output must render unavailable tenure")
}

// TestOutputDehashedJSONL_TenureUnavailable verifies that DeHashed JSONL includes
// a "tenure" key with available=false and the correct source/reason for each entry.
func TestOutputDehashedJSONL_TenureUnavailable(t *testing.T) {
	entries := []dehashed.Entry{
		{
			Email:     "carol@example.com",
			Databases: []string{"breach-db"},
			Count:     1,
			Tenure: enum.Tenure{
				Available: false,
				Source:    "dehashed",
				Reason:    "breach data, no employment dates",
			},
		},
	}
	var buf bytes.Buffer
	outputDehashedJSONL(&buf, entries, false)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))

	tenureMap, ok := obj["tenure"].(map[string]interface{})
	require.True(t, ok, "dehashed JSONL must include a 'tenure' object")
	assert.Equal(t, false, tenureMap["available"])
	assert.Equal(t, "dehashed", tenureMap["source"])
	assert.Equal(t, "breach data, no employment dates", tenureMap["reason"])
}

// ---------------------------------------------------------------------------
// Hunter: tenure in JSONL output
// ---------------------------------------------------------------------------

// TestOutputHunterJSONL_TenureUnavailable verifies that Hunter JSONL includes
// a "tenure" key with available=false and the correct source/reason.
func TestOutputHunterJSONL_TenureUnavailable(t *testing.T) {
	result := &hunter.DomainResult{
		Domain:       "example.com",
		Organization: "Example Inc",
		People: []hunter.Person{
			{
				Email:      "dave@example.com",
				FirstName:  "Dave",
				LastName:   "Smith",
				Confidence: 80,
				Tenure: enum.Tenure{
					Available: false,
					Source:    "hunter",
					Reason:    "no employment dates from source",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputHunterJSONL(&buf, result)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

	tenureMap, ok := obj["tenure"].(map[string]interface{})
	require.True(t, ok, "hunter JSONL must include a 'tenure' object")
	assert.Equal(t, false, tenureMap["available"])
	assert.Equal(t, "hunter", tenureMap["source"])
	assert.Equal(t, "no employment dates from source", tenureMap["reason"])
}

// TestOutputHunterHuman_TenureUnavailable verifies that the Hunter human output
// includes the Tenure column header and renders the unavailable reason.
func TestOutputHunterHuman_TenureUnavailable(t *testing.T) {
	result := &hunter.DomainResult{
		Domain:       "example.com",
		Organization: "Example Inc",
		People: []hunter.Person{
			{
				Email:      "dave@example.com",
				FirstName:  "Dave",
				LastName:   "Smith",
				Confidence: 80,
				Tenure: enum.Tenure{
					Available: false,
					Source:    "hunter",
					Reason:    "no employment dates from source",
				},
			},
		},
		Total: 1,
	}
	var buf bytes.Buffer
	outputHunterHuman(&buf, result, false)
	out := buf.String()

	assert.Contains(t, out, "Tenure", "hunter human output must include Tenure column header")
	assert.Contains(t, out, "unavailable", "hunter human output must render unavailable tenure reason")
}
