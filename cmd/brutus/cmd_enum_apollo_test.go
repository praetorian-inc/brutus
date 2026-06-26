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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/apollo"
)

// ---------------------------------------------------------------------------
// T004: resolveApolloAPIKey + classifyApolloError (security: no key leak)
// ---------------------------------------------------------------------------

func TestResolveApolloAPIKey(t *testing.T) {
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
			name:      "error when both empty — mentions APOLLO_API_KEY",
			flagValue: "",
			envValue:  "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APOLLO_API_KEY", tc.envValue)
			key, err := resolveApolloAPIKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "APOLLO_API_KEY",
					"error message must mention APOLLO_API_KEY so the operator knows what to set")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

// sentinelKey is deliberately placed in APIError.Details to simulate a vendor
// echoing back the API key inside an error body. classifyApolloError MUST NOT
// surface this value in its output (P0-1 security requirement).
const sentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"

func TestClassifyApolloError_NoKeyLeak(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "401 with sentinel in Details",
			err:  &apollo.APIError{StatusCode: 401, Details: sentinelKey},
		},
		{
			name: "429 rate limited",
			err:  &apollo.APIError{StatusCode: 429, Details: "rate limit"},
		},
		{
			name: "403 forbidden",
			err:  &apollo.APIError{StatusCode: 403, Details: "forbidden"},
		},
		{
			name: "422 bad request",
			err:  &apollo.APIError{StatusCode: 422, Details: "bad params"},
		},
		{
			name: "wrapped 500 with sentinel in Details",
			err:  fmt.Errorf("wrapped: %w", &apollo.APIError{StatusCode: 500, Details: sentinelKey}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := classifyApolloError(tc.err).Error()

			// P0-1: sentinel API key value must never appear in the output.
			assert.NotContains(t, out, sentinelKey,
				"API key value must never appear in classified error")

			// P0-1: header name must never appear in the output either.
			assert.NotContains(t, out, "X-Api-Key",
				"header name X-Api-Key must not appear in classified error")
		})
	}
}

// TestClassifyApolloError_NetworkWrap verifies that non-*APIError (network/DNS/
// timeout) errors are %w-wrapped by classifyApolloError so errors.Is chains work,
// while still not leaking any vendor details.
func TestClassifyApolloError_NetworkWrap(t *testing.T) {
	networkErr := errors.New("dial tcp: connection timeout")
	result := classifyApolloError(networkErr)
	require.Error(t, result)
	// The network error must be wrapped (errors.Is unwraps the chain).
	assert.True(t, errors.Is(result, networkErr),
		"classifyApolloError must %w-wrap non-*APIError so errors.Is works")
	// The error message must contain the original cause for debuggability.
	assert.Contains(t, result.Error(), "timeout")
}

// ---------------------------------------------------------------------------
// T005: runEnumApollo input validation (--limit < 0, --reveal with --limit 0)
// ---------------------------------------------------------------------------

// resetApolloFlags resets the package-level apollo flag vars to safe defaults.
// Reveal is DEFAULT-ON: flagApolloNoReveal=false means reveal is active.
func resetApolloFlags() {
	flagApolloDomain = "example.com"
	flagApolloTitles = nil
	flagApolloNoReveal = false
	flagApolloLimit = 100
	flagApolloAPIKey = ""
}

// TestRunEnumApollo_RejectsNegativeLimit asserts that --limit < 0 is rejected
// with an actionable error before any network call is made.
func TestRunEnumApollo_RejectsNegativeLimit(t *testing.T) {
	resetApolloFlags()
	flagApolloLimit = -1

	err := runEnumApollo(enumApolloCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit",
		"error must mention --limit so the operator knows what to fix")
}

// TestRunEnumApollo_RejectsRevealWithZeroLimit asserts that reveal (the DEFAULT)
// combined with --limit 0 (unbounded) is rejected to prevent unbounded credit
// spend. With reveal as default, --limit 0 alone must be rejected; passing
// --no-reveal (flagApolloNoReveal=true) with --limit 0 is allowed.
func TestRunEnumApollo_RejectsRevealWithZeroLimit(t *testing.T) {
	resetApolloFlags()
	// reveal is default (flagApolloNoReveal=false), so --limit 0 alone must fail.
	flagApolloLimit = 0

	err := runEnumApollo(enumApolloCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit",
		"error must mention --limit so the operator knows how to fix it")
}

// TestRunEnumApollo_AllowsNoRevealWithZeroLimit asserts that --no-reveal with
// --limit 0 (unbounded free discovery) is accepted.
func TestRunEnumApollo_AllowsNoRevealWithZeroLimit(t *testing.T) {
	resetApolloFlags()
	flagApolloNoReveal = true
	flagApolloLimit = 0

	// No API key set — runEnumApollo will fail on resolveApolloAPIKey, which is
	// expected; the important thing is it does NOT fail on the limit guard.
	t.Setenv("APOLLO_API_KEY", "")
	err := runEnumApollo(enumApolloCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APOLLO_API_KEY",
		"error must be about missing API key, not the limit guard")
	assert.NotContains(t, err.Error(), "--limit",
		"--no-reveal with --limit 0 must not be rejected by the limit guard")
}

// ---------------------------------------------------------------------------
// T003 cmd: outputApolloJSONL + outputApolloHuman
// ---------------------------------------------------------------------------

func TestOutputApolloJSONL(t *testing.T) {
	t.Run("preview person omits email field", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: false,
			People: []apollo.Person{
				{
					ID:           "p1",
					Name:         "Alice Smith",
					FirstName:    "Alice",
					LastName:     "Smith",
					Title:        "Engineer",
					Seniority:    "senior",
					Department:   "Engineering",
					Organization: "ACME Corp",
					// Email is empty — preview mode (no --reveal)
					Revealed: false,
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputApolloJSONL(&buf, result)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1, "expected exactly 1 JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "apollo", obj["type"])
		assert.Equal(t, "example.com", obj["domain"])
		assert.Equal(t, "p1", obj["id"])
		assert.Equal(t, false, obj["revealed"])

		// Preview mode: email must be omitted (omitempty) — not present as empty string.
		_, hasEmail := obj["email"]
		assert.False(t, hasEmail, "email must be omitted in preview JSONL (omitempty)")
		_, hasEmailStatus := obj["email_status"]
		assert.False(t, hasEmailStatus, "email_status must be omitted in preview JSONL (omitempty)")
	})

	t.Run("revealed person includes email", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: true,
			People: []apollo.Person{
				{
					ID:          "p1",
					Name:        "Alice Smith",
					Email:       "alice@example.com",
					EmailStatus: "verified",
					Revealed:    true,
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputApolloJSONL(&buf, result)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))

		assert.Equal(t, "alice@example.com", obj["email"])
		assert.Equal(t, "verified", obj["email_status"])
		assert.Equal(t, true, obj["revealed"])
	})

	t.Run("empty result emits zero lines", func(t *testing.T) {
		result := &apollo.DomainResult{Domain: "empty.com"}
		var buf bytes.Buffer
		outputApolloJSONL(&buf, result)
		assert.Empty(t, strings.TrimSpace(buf.String()), "empty result must produce no JSONL output")
	})
}

func TestOutputApolloHuman(t *testing.T) {
	t.Run("renders header and person row in preview mode", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: false,
			People: []apollo.Person{
				{
					ID:           "p1",
					Name:         "Alice Smith",
					Title:        "VP Engineering",
					Department:   "Engineering",
					Organization: "ACME Corp",
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputApolloHuman(&buf, result, false)
		out := buf.String()

		assert.Contains(t, out, "Apollo:")
		assert.Contains(t, out, "example.com")
		assert.Contains(t, out, "Alice Smith")
		assert.Contains(t, out, "VP Engineering")
		// Preview note must appear when not revealed.
		assert.Contains(t, out, "--reveal", "preview note must mention --reveal")
	})

	t.Run("revealed shows Email column and values", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: true,
			People: []apollo.Person{
				{
					ID:          "p1",
					Name:        "Alice Smith",
					Email:       "alice@example.com",
					EmailStatus: "verified",
					Revealed:    true,
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputApolloHuman(&buf, result, false)
		out := buf.String()

		assert.Contains(t, out, "Email")
		assert.Contains(t, out, "alice@example.com")
		assert.Contains(t, out, "verified")
	})

	t.Run("empty result shows no-people message", func(t *testing.T) {
		result := &apollo.DomainResult{Domain: "empty.com"}
		var buf bytes.Buffer
		outputApolloHuman(&buf, result, false)
		out := buf.String()
		assert.Contains(t, out, "No people found")
	})
}

// ---------------------------------------------------------------------------
// T006: enumApolloCmd registration
// ---------------------------------------------------------------------------

func TestEnumApolloRegistered(t *testing.T) {
	var found bool
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use != "apollo" {
			continue
		}
		found = true

		// Required flags must exist.
		domainFlag := cmd.Flags().Lookup("domain")
		require.NotNil(t, domainFlag, "--domain flag must exist")

		titlesFlag := cmd.Flags().Lookup("titles")
		require.NotNil(t, titlesFlag, "--titles flag must exist")

		revealFlag := cmd.Flags().Lookup("no-reveal")
		require.NotNil(t, revealFlag, "--no-reveal flag must exist")

		limitFlag := cmd.Flags().Lookup("limit")
		require.NotNil(t, limitFlag, "--limit flag must exist")

		apiKeyFlag := cmd.Flags().Lookup("api-key")
		require.NotNil(t, apiKeyFlag, "--api-key flag must exist")

		// -d shorthand must exist.
		domainShort := cmd.Flags().ShorthandLookup("d")
		require.NotNil(t, domainShort, "-d shorthand for --domain must exist")

		// --domain must be marked required via cobra annotation.
		annotations := domainFlag.Annotations
		_, isRequired := annotations["cobra_annotation_bash_completion_one_required_flag"]
		assert.True(t, isRequired, "--domain must be marked as required")

		break
	}
	require.True(t, found, "apollo subcommand must be registered with enumCmd")
}
