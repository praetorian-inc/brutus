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

	"github.com/spf13/cobra"
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
// Discover is the default (flagApolloEnrich=false). --enrich opts in to enrichment.
func resetApolloFlags() {
	flagApolloDomain = "example.com"
	flagApolloTitles = nil
	flagApolloEnrich = false
	flagApolloLimit = 100
	flagApolloAPIKey = ""
}

// TestRunEnumApollo_RejectsNegativeLimit asserts that --limit < 0 is rejected
// with an actionable error before any network call is made.
func TestRunEnumApollo_RejectsNegativeLimit(t *testing.T) {
	resetApolloFlags()
	flagApolloLimit = -1

	err := runEnumApollo(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit",
		"error must mention --limit so the operator knows what to fix")
}

// TestRunEnumApollo_DiscoverWithZeroLimitAllowed asserts that discover-only
// (default, flagApolloEnrich=false) with --limit 0 (unbounded) is accepted.
// Free discovery is safe to run without a limit cap.
func TestRunEnumApollo_DiscoverWithZeroLimitAllowed(t *testing.T) {
	resetApolloFlags()
	flagApolloEnrich = false
	flagApolloLimit = 0

	// No API key set — runEnumApollo will fail on resolveApolloAPIKey, which is
	// expected; the important thing is it does NOT fail on a limit guard.
	t.Setenv("APOLLO_API_KEY", "")
	err := runEnumApollo(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APOLLO_API_KEY",
		"error must be about missing API key, not a limit guard")
	assert.NotContains(t, err.Error(), "--limit",
		"discover with --limit 0 must not be rejected")
}

// TestRunEnumApollo_EnrichWithZeroLimitRejected asserts that --enrich with the
// default/unbounded --limit 0 is rejected up front: enrichment spends one credit
// per person, so an unbounded reveal must be refused before any network call.
func TestRunEnumApollo_EnrichWithZeroLimitRejected(t *testing.T) {
	resetApolloFlags()
	flagApolloEnrich = true
	flagApolloLimit = 0

	t.Setenv("APOLLO_API_KEY", "test-key")
	err := runEnumApollo(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--enrich",
		"error must mention --enrich")
	assert.Contains(t, err.Error(), "--limit",
		"error must tell the operator to set a positive --limit")
}

// TestRunEnumApollo_EnrichWithPositiveLimitPassesGuard asserts that --enrich with
// a positive --limit clears the credit-bound guard (it then fails later on the
// missing API key, NOT on the limit guard).
func TestRunEnumApollo_EnrichWithPositiveLimitPassesGuard(t *testing.T) {
	resetApolloFlags()
	flagApolloEnrich = true
	flagApolloLimit = 50

	t.Setenv("APOLLO_API_KEY", "")
	err := runEnumApollo(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APOLLO_API_KEY",
		"with a positive --limit the guard must pass; failure should be the missing key")
	assert.NotContains(t, err.Error(), "--enrich requires",
		"positive --limit must clear the --enrich credit guard")
}

// ---------------------------------------------------------------------------
// T003 cmd: outputApolloJSONL + outputApolloHuman
// ---------------------------------------------------------------------------

func TestOutputApolloJSONL(t *testing.T) {
	t.Run("discovery person emits has_email/has_phone availability, no email values", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: false,
			People: []apollo.Person{
				{
					ID:           "p1",
					Name:         "Alice Smith",
					FirstName:    "Alice",
					Title:        "Engineer",
					Organization: "ACME Corp",
					HasEmail:     true,
					HasPhone:     false,
					// Email is empty — discovery mode (no --enrich)
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

		// Discovery mode: availability flags must be present.
		assert.Equal(t, true, obj["has_email"], "has_email must be present in discovery JSONL")
		assert.Equal(t, false, obj["has_phone"], "has_phone must be present in discovery JSONL")

		// Discovery mode: email must be omitted (omitempty) — no PII revealed.
		_, hasEmail := obj["email"]
		assert.False(t, hasEmail, "email must be omitted in discovery JSONL (no PII)")
		_, hasEmailStatus := obj["email_status"]
		assert.False(t, hasEmailStatus, "email_status must be omitted in discovery JSONL")
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

	t.Run("revealed person retains has_email/has_phone availability", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:   "example.com",
			Revealed: true,
			People: []apollo.Person{
				{
					ID:       "p1",
					Name:     "Alice Smith",
					Email:    "alice@example.com",
					HasEmail: true,
					HasPhone: true,
					Revealed: true,
				},
			},
			Total: 1,
		}
		var buf bytes.Buffer
		outputApolloJSONL(&buf, result)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))
		assert.Equal(t, true, obj["has_email"], "enriched JSONL must retain has_email availability")
		assert.Equal(t, true, obj["has_phone"], "enriched JSONL must retain has_phone availability (phone is never revealed)")
	})

	t.Run("empty result emits zero lines", func(t *testing.T) {
		result := &apollo.DomainResult{Domain: "empty.com"}
		var buf bytes.Buffer
		outputApolloJSONL(&buf, result)
		assert.Empty(t, strings.TrimSpace(buf.String()), "empty result must produce no JSONL output")
	})
}

func TestOutputApolloHuman(t *testing.T) {
	t.Run("renders header and person row in discovery mode", func(t *testing.T) {
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
					HasEmail:     true,
					HasPhone:     false,
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
		// Discovery table must show availability columns, not email values.
		assert.Contains(t, out, "Email?", "discovery header must show Email? availability column")
		assert.Contains(t, out, "Phone?", "discovery header must show Phone? availability column")
		// Discovery note must mention --enrich (not --reveal).
		assert.Contains(t, out, "--enrich", "discovery note must mention --enrich")
	})

	t.Run("enriched shows Email column, values, and credits charged", func(t *testing.T) {
		result := &apollo.DomainResult{
			Domain:         "example.com",
			Revealed:       true,
			CreditsCharged: 1,
			People: []apollo.Person{
				{
					ID:          "p1",
					Name:        "Alice Smith",
					Email:       "alice@example.com",
					EmailStatus: "verified",
					HasPhone:    true,
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
		// Enriched output must report credits charged.
		assert.Contains(t, out, "credits charged", "enriched output must mention credits charged")
		assert.Contains(t, out, "Phone?", "enriched table must retain Phone? availability column (phone is not revealed)")
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
	// 1. enumCmd must have a "passive" subcommand.
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	// 2. The canonical "apollo" command must live under passive.
	var canonicalApollo *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "apollo" {
			canonicalApollo = cmd
			break
		}
	}
	require.NotNil(t, canonicalApollo, `"apollo" must be a subcommand of enumPassiveCmd`)

	// Verify expected flags on the canonical command: --enrich replaces --no-reveal.
	for _, flagName := range []string{"domain", "titles", "enrich", "limit", "api-key"} {
		require.NotNilf(t, canonicalApollo.Flags().Lookup(flagName),
			"--%s flag must exist on canonical apollo", flagName)
	}

	// --no-reveal must NOT exist (it was removed in the discover→enrich split).
	assert.Nilf(t, canonicalApollo.Flags().Lookup("no-reveal"),
		"--no-reveal must not exist on the apollo command (replaced by --enrich)")

	domainShort := canonicalApollo.Flags().ShorthandLookup("d")
	require.NotNil(t, domainShort, "-d shorthand for --domain must exist")

	domainFlag := canonicalApollo.Flags().Lookup("domain")
	_, isRequired := domainFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, isRequired, "--domain must be marked as required")

	// 3. A hidden back-compat alias must exist directly under enumCmd.
	var alias *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "apollo" {
			alias = cmd
			break
		}
	}
	require.NotNil(t, alias, `hidden "apollo" alias must be registered directly under enumCmd`)
	assert.True(t, alias.Hidden, "back-compat apollo alias must be Hidden")
	assert.NotEmpty(t, alias.Deprecated, "back-compat apollo alias must be Deprecated")
}
