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

	"github.com/praetorian-inc/brutus/pkg/enum/hunter"
)

// ---------------------------------------------------------------------------
// Task 4: resolveHunterAPIKey + classifyHunterError
// ---------------------------------------------------------------------------

func TestResolveHunterAPIKey(t *testing.T) {
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
			name:      "error when both empty",
			flagValue: "",
			envValue:  "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HUNTER_API_KEY", tc.envValue)
			key, err := resolveHunterAPIKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "HUNTER_API_KEY")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

func TestClassifyHunterError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantContain string
	}{
		{
			name:        "ErrUnauthorized maps to key message",
			err:         &hunter.APIError{StatusCode: 401, Details: "No valid API key"},
			wantContain: "invalid or missing API key",
		},
		{
			name:        "ErrRateLimited maps to rate limit message",
			err:         &hunter.APIError{StatusCode: 429, Details: "rate limit"},
			wantContain: "rate limit exceeded",
		},
		{
			name:        "ErrLegalReasons maps to legal message",
			err:         &hunter.APIError{StatusCode: 451, Details: "legal"},
			wantContain: "legal reasons",
		},
		{
			name:        "generic error is wrapped",
			err:         &hunter.APIError{StatusCode: 500, Details: "server error"},
			wantContain: "hunter domain search failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyHunterError(tc.err)
			require.Error(t, result)
			assert.Contains(t, result.Error(), tc.wantContain)
			// Key must never appear in error messages (P0-1 security requirement).
			assert.NotContains(t, result.Error(), "api_key")
		})
	}
}

// ---------------------------------------------------------------------------
// Task 5: Command registration
// ---------------------------------------------------------------------------

func TestEnumHunterRegistered(t *testing.T) {
	// 1. enumCmd must have a "passive" subcommand.
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	// 2. The canonical "hunter" command must live under passive.
	var canonicalHunter *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "hunter" {
			canonicalHunter = cmd
			break
		}
	}
	require.NotNil(t, canonicalHunter, `"hunter" must be a subcommand of enumPassiveCmd`)

	// Verify expected flags on the canonical command (cross-check with builder).
	ref := newEnumHunterCmd()
	for _, flagName := range []string{"domain", "api-key", "limit"} {
		require.NotNilf(t, canonicalHunter.Flags().Lookup(flagName),
			"--%s flag must exist on canonical hunter", flagName)
		require.NotNilf(t, ref.Flags().Lookup(flagName),
			"--%s flag must exist on builder output", flagName)
	}
	domainShort := canonicalHunter.Flags().ShorthandLookup("d")
	require.NotNil(t, domainShort, "-d shorthand must exist")

	domainFlag := canonicalHunter.Flags().Lookup("domain")
	_, isRequired := domainFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, isRequired, "--domain must be marked as required")

	// 3. A hidden back-compat alias must exist directly under enumCmd.
	var alias *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "hunter" {
			alias = cmd
			break
		}
	}
	require.NotNil(t, alias, `hidden "hunter" alias must be registered directly under enumCmd`)
	assert.True(t, alias.Hidden, "back-compat hunter alias must be Hidden")
	assert.NotEmpty(t, alias.Deprecated, "back-compat hunter alias must be Deprecated")
}

// ---------------------------------------------------------------------------
// Task 6: outputHunterJSONL + outputHunterHuman + sanitizeTerminal + truncate
// ---------------------------------------------------------------------------

func TestOutputHunterJSONL(t *testing.T) {
	t.Run("single person emits one JSONL line", func(t *testing.T) {
		result := &hunter.DomainResult{
			Domain:       "example.com",
			Organization: "Example Corp",
			People: []hunter.Person{
				{
					Email:      "alice@example.com",
					FirstName:  "Alice",
					LastName:   "Smith",
					Position:   "Engineer",
					Confidence: 90,
					Type:       "personal",
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputHunterJSONL(&buf, result)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1, "expected exactly 1 JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))
		assert.Equal(t, "hunter", obj["type"])
		assert.Equal(t, "alice@example.com", obj["email"])
		assert.Equal(t, float64(90), obj["confidence"])
		assert.Equal(t, "Example Corp", obj["organization"])
		assert.Equal(t, "example.com", obj["domain"])
	})

	t.Run("omitempty drops blank fields", func(t *testing.T) {
		result := &hunter.DomainResult{
			Domain: "test.com",
			People: []hunter.Person{
				{Email: "bob@test.com", Confidence: 50},
			},
		}
		var buf bytes.Buffer
		outputHunterJSONL(&buf, result)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))
		// Empty string fields with omitempty must not appear.
		_, hasFirstName := obj["first_name"]
		assert.False(t, hasFirstName, "empty first_name should be omitted")
		_, hasOrg := obj["organization"]
		assert.False(t, hasOrg, "empty organization should be omitted")
		_, hasSources := obj["sources"]
		assert.False(t, hasSources, "nil sources should be omitted")
	})

	t.Run("empty result emits zero lines", func(t *testing.T) {
		result := &hunter.DomainResult{Domain: "empty.com"}
		var buf bytes.Buffer
		outputHunterJSONL(&buf, result)
		assert.Empty(t, strings.TrimSpace(buf.String()), "empty result must produce no JSONL output")
	})

	t.Run("multiple people emit multiple lines each valid JSON", func(t *testing.T) {
		result := &hunter.DomainResult{
			Domain: "multi.com",
			People: []hunter.Person{
				{Email: "a@multi.com", Confidence: 80},
				{Email: "b@multi.com", Confidence: 60},
				{Email: "c@multi.com", Confidence: 40},
			},
		}
		var buf bytes.Buffer
		outputHunterJSONL(&buf, result)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 3)
		for i, line := range lines {
			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj), "line %d must be valid JSON", i)
			assert.Equal(t, "hunter", obj["type"])
		}
	})
}

func TestOutputHunterHuman(t *testing.T) {
	t.Run("renders table header and person row", func(t *testing.T) {
		result := &hunter.DomainResult{
			Domain:       "example.com",
			Organization: "Example Corp",
			People: []hunter.Person{
				{
					Email:      "alice@example.com",
					FirstName:  "Alice",
					LastName:   "Smith",
					Position:   "Engineer",
					Phone:      "+1-555-0100",
					Department: "Engineering",
					Confidence: 90,
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputHunterHuman(&buf, result, false)
		out := buf.String()
		assert.Contains(t, out, "Email")
		assert.Contains(t, out, "alice@example.com")
		assert.Contains(t, out, "Example Corp")
	})

	t.Run("graceful empty result message", func(t *testing.T) {
		result := &hunter.DomainResult{Domain: "empty.com", Total: 0}
		var buf bytes.Buffer
		outputHunterHuman(&buf, result, false)
		out := buf.String()
		assert.Contains(t, out, "No people found")
	})
}

func TestSanitizeTerminal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "strips ESC cursor movement sequence",
			input: "hello\x1b[2Jworld",
			want:  "helloworld",
		},
		{
			name:  "strips lone ESC",
			input: "ab\x1bcd",
			want:  "abcd",
		},
		{
			name:  "strips C0 control chars",
			input: "ab\x00\x01\x02cd",
			want:  "abcd",
		},
		{
			name:  "strips tab and newline (C0)",
			input: "ab\tcd\nef",
			want:  "abcdef",
		},
		{
			name:  "preserves printable ASCII and spaces",
			input: "Alice Smith",
			want:  "Alice Smith",
		},
		{
			name:  "strips C1 control chars",
			input: "ab\x80\x9fcd",
			want:  "abcd",
		},
		{
			name:  "handles empty string",
			input: "",
			want:  "",
		},
		{
			name:  "strips full ANSI erase sequence",
			input: "\x1b[2Jsome text\x1b[H",
			want:  "some text",
		},
		{
			name:  "preserves valid non-ASCII UTF-8 (accented Latin)",
			input: "\u00c5ngstr\u00f6m",
			want:  "\u00c5ngstr\u00f6m",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTerminal(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncates with ellipsis", "hello world", 8, "hello w\u2026"},
		{"max 1 returns single char", "abc", 1, "a"},
		{"empty string unchanged", "", 5, ""},
		{"unicode handled correctly", "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8", 4, "\u65e5\u672c\u8a9e\u2026"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.s, tc.max)
			assert.Equal(t, tc.want, got)
		})
	}
}
