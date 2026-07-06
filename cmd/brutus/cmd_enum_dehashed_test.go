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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/dehashed"
)

// sentinel key used to verify no leakage through error messages.
const dehashedTestSentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"

// ---------------------------------------------------------------------------
// Task 7: resolveDehashedAPIKey
// ---------------------------------------------------------------------------

func TestResolveDehashedAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envValue  string
		wantKey   string
		wantErr   bool
	}{
		{
			name:      "flag value takes priority over env",
			flagValue: "flag-key",
			envValue:  "env-key",
			wantKey:   "flag-key",
		},
		{
			name:      "env var used when flag is empty",
			flagValue: "",
			envValue:  "env-key",
			wantKey:   "env-key",
		},
		{
			name:      "error when both empty mentions DEHASHED_API_KEY",
			flagValue: "",
			envValue:  "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEHASHED_API_KEY", tc.envValue)
			key, err := resolveDehashedAPIKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "DEHASHED_API_KEY")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

// ---------------------------------------------------------------------------
// Task 8: classifyDehashedError — key must never appear in output
// ---------------------------------------------------------------------------

func TestClassifyDehashedError_NoKeyLeak(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantContain string
	}{
		{
			name:        "401 → invalid or missing API key message",
			err:         &dehashed.APIError{StatusCode: 401, Details: dehashedTestSentinelKey},
			wantContain: "invalid or missing API key",
		},
		{
			name:        "402 → payment required message",
			err:         &dehashed.APIError{StatusCode: 402, Details: dehashedTestSentinelKey},
			wantContain: "payment required",
		},
		{
			name:        "403 → access forbidden message",
			err:         &dehashed.APIError{StatusCode: 403, Details: dehashedTestSentinelKey},
			wantContain: "forbidden",
		},
		{
			name:        "429 → rate limit message",
			err:         &dehashed.APIError{StatusCode: 429, Details: dehashedTestSentinelKey},
			wantContain: "rate limit",
		},
		{
			name:        "500 → generic HTTP status code only",
			err:         &dehashed.APIError{StatusCode: 500, Details: dehashedTestSentinelKey},
			wantContain: "500",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyDehashedError(tc.err)
			require.Error(t, result)
			msg := result.Error()

			// Must contain the expected human-readable portion.
			assert.Contains(t, msg, tc.wantContain)

			// Sentinel key must NEVER appear in the error message (P0-1).
			assert.NotContains(t, msg, dehashedTestSentinelKey, "API key must not leak into error message")
			// Header name must not appear either.
			assert.NotContains(t, msg, "Dehashed-Api-Key", "header name must not appear in error message")
		})
	}
}

// ---------------------------------------------------------------------------
// Task 9 (updated): outputDehashedHuman — showCredentials bool param
// ---------------------------------------------------------------------------

func TestOutputDehashedHuman(t *testing.T) {
	t.Run("renders entries with email name username phone sources columns", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "alice@example.com",
				Names:     []string{"Alice Smith"},
				Usernames: []string{"alice"},
				Phones:    []string{"+1-555-0100"},
				Databases: []string{"breach-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "example.com", 1, 10, 500, entries, false, false)
		out := buf.String()

		// Column headers must be present.
		assert.Contains(t, out, "Email")
		assert.Contains(t, out, "Name")
		assert.Contains(t, out, "Username")
		assert.Contains(t, out, "Phone")
		assert.Contains(t, out, "Sources")

		// No "Date" column (date was removed from Entry).
		assert.NotContains(t, out, "Date")

		// Data values must appear.
		assert.Contains(t, out, "alice@example.com")
		assert.Contains(t, out, "Alice Smith")
		assert.Contains(t, out, "alice")
		assert.Contains(t, out, "+1-555-0100")
		assert.Contains(t, out, "breach-db")
	})

	t.Run("phone column value rendered", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "bob@example.com",
				Phones:    []string{"+44-7700-900000"},
				Databases: []string{"some-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "example.com", 1, 1, 0, entries, false, false)
		out := buf.String()
		assert.Contains(t, out, "+44-7700-900000", "phone value must appear in human output")
	})

	t.Run("summary line contains rawFetched → unique contacts", func(t *testing.T) {
		entries := []dehashed.Entry{
			{Email: "a@example.com", Databases: []string{"DB1"}, Count: 1},
			{Email: "b@example.com", Databases: []string{"DB2"}, Count: 1},
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "example.com", 5, 100, 0, entries, false, false)
		out := buf.String()
		// Summary: "5 records → 2 unique contacts"
		assert.Contains(t, out, "5 records")
		assert.Contains(t, out, "2 unique contacts")
	})

	t.Run("empty entries shows no matching records message", func(t *testing.T) {
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "empty.com", 0, 0, 0, []dehashed.Entry{}, false, false)
		out := buf.String()
		assert.Contains(t, out, "No matching records for this domain")
	})

	// showCredentials=false: the Password(s) column and values must NOT appear.
	t.Run("showCredentials=false: no Password(s) column and no password values", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "bob@example.com",
				Usernames: []string{"bob"},
				Passwords: []string{"secret123"},
				Databases: []string{"some-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "example.com", 1, 1, 0, entries, false, false)
		out := buf.String()
		outLower := strings.ToLower(out)
		assert.NotContains(t, outLower, "password", "Password(s) column must not appear when showCredentials=false")
		assert.NotContains(t, out, "secret123", "password value must not appear when showCredentials=false")
		assert.NotContains(t, outLower, "hashed_password", "hashed_password must never appear in human output")
	})

	// showCredentials=true: the Password(s) column header AND values must appear.
	t.Run("showCredentials=true: Password(s) column and values appear", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "carol@example.com",
				Passwords: []string{"hunter2", "p@ss"},
				Databases: []string{"breach-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, "example.com", 1, 1, 0, entries, false, true)
		out := buf.String()
		assert.Contains(t, out, "Password(s)", "Password(s) column header must appear when showCredentials=true")
		assert.Contains(t, out, "hunter2", "password value must appear when showCredentials=true")
		assert.Contains(t, out, "p@ss", "all password values must appear when showCredentials=true")
		// hashed_password must never appear regardless of showCredentials.
		assert.NotContains(t, strings.ToLower(out), "hashed_password",
			"hashed_password must never appear in human output")
	})
}

// ---------------------------------------------------------------------------
// Task 10 (updated): outputDehashedJSONL — showCredentials bool param
// ---------------------------------------------------------------------------

func TestOutputDehashedJSONL(t *testing.T) {
	t.Run("single entry emits one JSONL line with expected fields", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "alice@example.com",
				Names:     []string{"Alice Smith"},
				Usernames: []string{"alice"},
				Phones:    []string{"+1-555-0100"},
				Databases: []string{"breach-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, entries, false)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "dehashed", obj["type"])
		assert.Equal(t, "alice@example.com", obj["email"])

		// Names, usernames, phones must be present.
		names, ok := obj["names"].([]interface{})
		require.True(t, ok, "names must be array")
		assert.Equal(t, "Alice Smith", names[0])

		usernames, ok := obj["usernames"].([]interface{})
		require.True(t, ok, "usernames must be array")
		assert.Equal(t, "alice", usernames[0])

		phones, ok := obj["phones"].([]interface{})
		require.True(t, ok, "phones must be array")
		assert.Equal(t, "+1-555-0100", phones[0])

		// Databases must include the source DB.
		dbs, ok := obj["databases"].([]interface{})
		require.True(t, ok, "databases must be array")
		assert.Equal(t, "breach-db", dbs[0])

		// Count must be present.
		count, ok := obj["count"].(float64)
		require.True(t, ok, "count must be a number")
		assert.Equal(t, float64(1), count)
	})

	t.Run("phones appear in JSONL output", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "carol@example.com",
				Phones:    []string{"+1-800-555-1234"},
				Databases: []string{"some-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, entries, false)
		out := buf.String()
		assert.Contains(t, out, "+1-800-555-1234", "phone must appear in JSONL output")
	})

	// showCredentials=false: "passwords" key must not appear, hashed_password never.
	t.Run("showCredentials=false: no passwords key in JSONL output", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "alice@example.com",
				Passwords: []string{"secret123"},
				Databases: []string{"breach-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, entries, false)
		out := strings.ToLower(buf.String())
		assert.NotContains(t, out, `"passwords"`, "passwords key must not appear in JSONL when showCredentials=false")
		assert.NotContains(t, out, "secret123", "password value must not appear in JSONL when showCredentials=false")
		assert.NotContains(t, out, "hashed_password", "hashed_password key must never appear in JSONL output")
	})

	// showCredentials=true: "passwords" key AND values must appear.
	t.Run("showCredentials=true: passwords key and values appear in JSONL output", func(t *testing.T) {
		entries := []dehashed.Entry{
			{
				Email:     "bob@example.com",
				Passwords: []string{"hunter2", "p@ss"},
				Databases: []string{"breach-db"},
				Count:     1,
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, entries, true)
		out := buf.String()

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &obj))

		passwords, ok := obj["passwords"].([]interface{})
		require.True(t, ok, "passwords must be a JSON array when showCredentials=true")
		var pwStrings []string
		for _, p := range passwords {
			s, ok := p.(string)
			require.True(t, ok)
			pwStrings = append(pwStrings, s)
		}
		assert.ElementsMatch(t, []string{"hunter2", "p@ss"}, pwStrings,
			"passwords values must appear in JSONL when showCredentials=true")
		// hashed_password must never appear regardless of showCredentials.
		assert.NotContains(t, strings.ToLower(out), "hashed_password",
			"hashed_password must never appear in JSONL output")
	})

	t.Run("empty entries emits zero lines", func(t *testing.T) {
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, []dehashed.Entry{}, false)
		assert.Empty(t, strings.TrimSpace(buf.String()))
	})

	t.Run("multiple entries emit multiple valid JSON lines", func(t *testing.T) {
		entries := []dehashed.Entry{
			{Email: "a@example.com", Databases: []string{"DB1"}, Count: 1},
			{Email: "b@example.com", Databases: []string{"DB2"}, Count: 1},
			{Email: "c@example.com", Databases: []string{"DB3"}, Count: 1},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, entries, false)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 3)
		for i, line := range lines {
			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj), "line %d must be valid JSON", i)
			assert.Equal(t, "dehashed", obj["type"])
		}
	})
}

// ---------------------------------------------------------------------------
// Task 11: enumDehashedCmd registration and flags (updated — passive regroup)
// ---------------------------------------------------------------------------

func TestEnumDehashedRegistered(t *testing.T) {
	// 1. enumCmd must have a "passive" subcommand.
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	// 2. The canonical "dehashed" command must live under passive.
	var canonicalDehashed *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "dehashed" {
			canonicalDehashed = cmd
			break
		}
	}
	require.NotNil(t, canonicalDehashed, `"dehashed" must be a subcommand of enumPassiveCmd`)

	// Verify expected flags on the canonical command.
	domainFlag := canonicalDehashed.Flags().Lookup("domain")
	require.NotNil(t, domainFlag, "--domain flag must exist")

	apiKeyFlag := canonicalDehashed.Flags().Lookup("api-key")
	require.NotNil(t, apiKeyFlag, "--api-key flag must exist")

	limitFlag := canonicalDehashed.Flags().Lookup("limit")
	require.NotNil(t, limitFlag, "--limit flag must exist")

	domainShort := canonicalDehashed.Flags().ShorthandLookup("d")
	require.NotNil(t, domainShort, "-d shorthand must exist")

	_, isRequired := domainFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, isRequired, "--domain must be marked as required")

	assert.Equal(t, "100", limitFlag.DefValue, "--limit default must be 100")

	allEmailsFlag := canonicalDehashed.Flags().Lookup("all-emails")
	require.NotNil(t, allEmailsFlag, "--all-emails flag must exist")

	nodedupFlag := canonicalDehashed.Flags().Lookup("no-dedup")
	require.NotNil(t, nodedupFlag, "--no-dedup flag must exist")

	excludeCombolistsFlag := canonicalDehashed.Flags().Lookup("exclude-combolists")
	require.NotNil(t, excludeCombolistsFlag, "--exclude-combolists flag must exist")
	assert.Equal(t, "false", excludeCombolistsFlag.DefValue, "--exclude-combolists default must be false (combolists included by default)")

	noCredentialsFlag := canonicalDehashed.Flags().Lookup("no-credentials")
	require.NotNil(t, noCredentialsFlag, "--no-credentials flag must exist")
	assert.Equal(t, "false", noCredentialsFlag.DefValue, "--no-credentials default must be false (passwords shown by default)")

	// 3. A hidden back-compat alias must exist directly under enumCmd.
	var alias *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "dehashed" {
			alias = cmd
			break
		}
	}
	require.NotNil(t, alias, `hidden "dehashed" alias must be registered directly under enumCmd`)
	assert.True(t, alias.Hidden, "back-compat dehashed alias must be Hidden")
	assert.NotEmpty(t, alias.Deprecated, "back-compat dehashed alias must be Deprecated")
}
