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
// Task 9: outputDehashedHuman
// ---------------------------------------------------------------------------

func TestOutputDehashedHuman(t *testing.T) {
	t.Run("renders records with email username name database", func(t *testing.T) {
		result := &dehashed.DomainResult{
			Domain: "example.com",
			Records: []dehashed.Record{
				{
					ID:       "1",
					Email:    []string{"alice@example.com"},
					Username: []string{"alice"},
					Name:     []string{"Alice Smith"},
					Database: "breach-db",
				},
			},
			Total:   1,
			Balance: 500,
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, result, false)
		out := buf.String()
		assert.Contains(t, out, "Email")
		assert.Contains(t, out, "alice@example.com")
		assert.Contains(t, out, "alice")
		assert.Contains(t, out, "Alice Smith")
		assert.Contains(t, out, "breach-db")
	})

	t.Run("empty result shows no records found message", func(t *testing.T) {
		result := &dehashed.DomainResult{Domain: "empty.com", Total: 0}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, result, false)
		out := buf.String()
		assert.Contains(t, out, "No records found")
	})

	t.Run("no password or hashed_password in output", func(t *testing.T) {
		result := &dehashed.DomainResult{
			Domain: "example.com",
			Records: []dehashed.Record{
				{
					Email:    []string{"bob@example.com"},
					Username: []string{"bob"},
					Database: "some-db",
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputDehashedHuman(&buf, result, false)
		out := strings.ToLower(buf.String())
		assert.NotContains(t, out, "password", "password must never appear in human output")
		assert.NotContains(t, out, "hashed_password", "hashed_password must never appear in human output")
	})
}

// ---------------------------------------------------------------------------
// Task 10: outputDehashedJSONL
// ---------------------------------------------------------------------------

func TestOutputDehashedJSONL(t *testing.T) {
	t.Run("single record emits one JSONL line with type dehashed", func(t *testing.T) {
		result := &dehashed.DomainResult{
			Domain: "example.com",
			Records: []dehashed.Record{
				{
					ID:       "r1",
					Email:    []string{"alice@example.com"},
					Username: []string{"alice"},
					Name:     []string{"Alice Smith"},
					Database: "breach-db",
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, result)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))
		assert.Equal(t, "dehashed", obj["type"])
		assert.Equal(t, "example.com", obj["domain"])
		assert.Equal(t, "r1", obj["id"])
	})

	t.Run("empty result emits zero lines", func(t *testing.T) {
		result := &dehashed.DomainResult{Domain: "empty.com"}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, result)
		assert.Empty(t, strings.TrimSpace(buf.String()))
	})

	t.Run("multiple records emit multiple valid JSON lines", func(t *testing.T) {
		result := &dehashed.DomainResult{
			Domain: "multi.com",
			Records: []dehashed.Record{
				{Email: []string{"a@multi.com"}},
				{Email: []string{"b@multi.com"}},
				{Email: []string{"c@multi.com"}},
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, result)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 3)
		for i, line := range lines {
			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj), "line %d must be valid JSON", i)
			assert.Equal(t, "dehashed", obj["type"])
		}
	})

	t.Run("no password or hashed_password keys in JSONL output", func(t *testing.T) {
		result := &dehashed.DomainResult{
			Domain: "example.com",
			Records: []dehashed.Record{
				{
					Email:    []string{"alice@example.com"},
					Database: "breach-db",
				},
			},
		}
		var buf bytes.Buffer
		outputDehashedJSONL(&buf, result)
		out := strings.ToLower(buf.String())
		assert.NotContains(t, out, `"password"`, "password key must never appear in JSONL output")
		assert.NotContains(t, out, "hashed_password", "hashed_password key must never appear in JSONL output")
	})
}

// ---------------------------------------------------------------------------
// Task 11: enumDehashedCmd registration and flags
// ---------------------------------------------------------------------------

func TestEnumDehashedRegistered(t *testing.T) {
	var found bool
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use != "dehashed" {
			continue
		}
		found = true

		domainFlag := cmd.Flags().Lookup("domain")
		require.NotNil(t, domainFlag, "--domain flag must exist")

		apiKeyFlag := cmd.Flags().Lookup("api-key")
		require.NotNil(t, apiKeyFlag, "--api-key flag must exist")

		limitFlag := cmd.Flags().Lookup("limit")
		require.NotNil(t, limitFlag, "--limit flag must exist")

		// Verify -d shorthand exists.
		domainShort := cmd.Flags().ShorthandLookup("d")
		require.NotNil(t, domainShort, "-d shorthand must exist")

		// Verify --domain is marked required via cobra annotation.
		annotations := domainFlag.Annotations
		_, isRequired := annotations["cobra_annotation_bash_completion_one_required_flag"]
		assert.True(t, isRequired, "--domain must be marked as required")

		// Verify --limit default value is 100.
		assert.Equal(t, "100", limitFlag.DefValue, "--limit default must be 100")

		break
	}
	require.True(t, found, "dehashed subcommand must be registered with enumCmd")
}
