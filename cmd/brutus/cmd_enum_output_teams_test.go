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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// Test: outputTeamsEnumResultLine — account-type suffix for EXISTS results
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumResultLine_AccountType(t *testing.T) {
	tests := []struct {
		name        string
		result      teams.EnumResult
		wantContain string
		wantAbsent  []string
	}{
		{
			name: "corporate MRI appends (corporate)",
			result: teams.EnumResult{
				Email:       "alice@contoso.com",
				Exists:      teams.ExistenceYes,
				DisplayName: "Alice",
				MRI:         "8:orgid:abc",
			},
			wantContain: "(corporate)",
			wantAbsent:  []string{"(consumer)"},
		},
		{
			name: "consumer MRI appends (consumer)",
			result: teams.EnumResult{
				Email:       "bob@live.com",
				Exists:      teams.ExistenceYes,
				DisplayName: "Bob",
				MRI:         "8:live:.cid.x",
			},
			wantContain: "(consumer)",
			wantAbsent:  []string{"(corporate)"},
		},
		{
			name: "BLOCKED result renders blocked label and no account-type suffix",
			result: teams.EnumResult{
				Email:  "blocked@contoso.com",
				Exists: teams.ExistenceBlocked,
			},
			wantContain: "BLOCKED",
			wantAbsent:  []string{"(corporate)", "(consumer)"},
		},
		{
			name: "EXISTS with unknown MRI prefix has no account-type suffix",
			result: teams.EnumResult{
				Email:  "weird@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "weird:mri:value",
			},
			wantAbsent: []string{"(corporate)", "(consumer)"},
		},
		{
			name: "NOT FOUND result has no account-type suffix",
			result: teams.EnumResult{
				Email:  "notfound@contoso.com",
				Exists: teams.ExistenceNo,
			},
			wantAbsent: []string{"(corporate)", "(consumer)"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputTeamsEnumResultLine(&buf, tc.result, false /* useColor */)
			out := buf.String()

			if tc.wantContain != "" {
				assert.Contains(t, out, tc.wantContain,
					"output line must contain %q", tc.wantContain)
			}
			for _, absent := range tc.wantAbsent {
				assert.NotContains(t, out, absent,
					"output line must not contain %q", absent)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: outputTeamsEnumResultLine — server strings are sanitized (ANSI strip)
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumResultLine_Sanitizes(t *testing.T) {
	tests := []struct {
		name   string
		result teams.EnumResult
	}{
		{
			name: "ANSI escape in DisplayName is stripped",
			result: teams.EnumResult{
				Email:       "evil@contoso.com",
				Exists:      teams.ExistenceYes,
				DisplayName: "\x1b[31mRED NAME\x1b[0m",
				MRI:         "8:orgid:abc",
			},
		},
		{
			name: "ANSI escape in MRI is stripped",
			result: teams.EnumResult{
				Email:  "evil2@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "\x1b[31m8:orgid:abc",
			},
		},
		{
			name: "ANSI escape in Email is stripped",
			result: teams.EnumResult{
				Email:  "e\x1b[31mvil@contoso.com",
				Exists: teams.ExistenceNo,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputTeamsEnumResultLine(&buf, tc.result, false)
			out := buf.String()

			assert.NotContains(t, out, "\x1b",
				"raw ESC byte 0x1B must be absent from the rendered line")
		})
	}
}

// ---------------------------------------------------------------------------
// Test: outputTeamsEnumJSONL — account_type field presence and values
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumJSONL_AccountType(t *testing.T) {
	tests := []struct {
		name            string
		result          teams.EnumResult
		wantAccountType string // expected "account_type" value; "" means key must be absent
	}{
		{
			name: "8:orgid MRI -> account_type corporate",
			result: teams.EnumResult{
				Email:  "alice@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "8:orgid:some-guid",
			},
			wantAccountType: "corporate",
		},
		{
			name: "8:live MRI -> account_type consumer",
			result: teams.EnumResult{
				Email:  "bob@live.com",
				Exists: teams.ExistenceYes,
				MRI:    "8:live:.cid.456",
			},
			wantAccountType: "consumer",
		},
		{
			name: "empty MRI -> account_type omitted (omitempty)",
			result: teams.EnumResult{
				Email:  "charlie@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "",
			},
			wantAccountType: "", // omitempty: key must not appear
		},
		{
			name: "unknown MRI prefix -> account_type omitted (omitempty)",
			result: teams.EnumResult{
				Email:  "dave@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "weird:mri:value",
			},
			wantAccountType: "", // AccountType returns "" -> omitempty drops the key
		},
		{
			name: "ExistenceNo with empty MRI -> account_type omitted",
			result: teams.EnumResult{
				Email:  "nobody@contoso.com",
				Exists: teams.ExistenceNo,
			},
			wantAccountType: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputTeamsEnumJSONL(&buf, []teams.EnumResult{tc.result})

			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			require.Len(t, lines, 1, "must emit exactly one JSONL line per result")

			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj),
				"JSONL line must be valid JSON")

			// Verify account_type field.
			if tc.wantAccountType != "" {
				val, ok := obj["account_type"]
				require.True(t, ok, "account_type key must be present for MRI %q", tc.result.MRI)
				assert.Equal(t, tc.wantAccountType, val,
					"account_type value must be %q for MRI %q", tc.wantAccountType, tc.result.MRI)
			} else {
				_, ok := obj["account_type"]
				assert.False(t, ok,
					"account_type key must be absent (omitempty) for MRI %q", tc.result.MRI)
			}

			// Token fields must never appear in JSONL output (P0-1).
			for _, field := range []string{"access_token", "refresh_token", "id_token"} {
				assert.NotContains(t, lines[0], field,
					"JSONL output must never contain token field %q", field)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: outputTeamsEnumJSONL — error result encodes correctly, no token fields
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumJSONL_ErrorResult(t *testing.T) {
	results := []teams.EnumResult{
		{
			Email:  "error@contoso.com",
			Exists: teams.ExistenceUnknown,
			Error:  errors.New("teams enum: unexpected status 500"),
		},
	}

	var buf bytes.Buffer
	outputTeamsEnumJSONL(&buf, results)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

	assert.Equal(t, "teams_enum", obj["type"])
	assert.Equal(t, "error@contoso.com", obj["email"])
	assert.Equal(t, string(teams.ExistenceUnknown), obj["exists"])
	assert.NotEmpty(t, obj["error"], "error field must be present for error results")

	// account_type must be absent for an error result with no MRI.
	_, ok := obj["account_type"]
	assert.False(t, ok, "account_type must be absent for result with empty MRI")

	// Token fields must never appear.
	for _, field := range []string{"access_token", "refresh_token", "id_token"} {
		assert.NotContains(t, lines[0], field,
			"JSONL output must never contain token field %q", field)
	}
}
