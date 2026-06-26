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

	"github.com/praetorian-inc/brutus/pkg/enum/lusha"
)

// ---------------------------------------------------------------------------
// T103: outputLushaJSONL + outputLushaHuman
// ---------------------------------------------------------------------------

func TestOutputLushaJSONL(t *testing.T) {
	t.Run("contact with email and DNC phone emits one JSON line", func(t *testing.T) {
		c := &lusha.Contact{
			Name:     "Ada Lovelace",
			JobTitle: "Mathematician",
			Company:  "AnalyticalCo",
			Emails: []lusha.EmailEntry{
				{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			},
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0100", Type: "direct", DoNotCall: true},
			},
		}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1, "expected exactly 1 JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))
		assert.Equal(t, "lusha", obj["type"])
		assert.Equal(t, "Ada Lovelace", obj["name"])
		assert.Equal(t, "Mathematician", obj["job_title"])
		assert.Equal(t, "AnalyticalCo", obj["company"])

		emails, ok := obj["emails"].([]interface{})
		require.True(t, ok, "emails must be a JSON array")
		require.Len(t, emails, 1)
		email := emails[0].(map[string]interface{})
		assert.Equal(t, "ada@example.com", email["address"])

		phones, ok := obj["phones"].([]interface{})
		require.True(t, ok, "phones must be a JSON array")
		require.Len(t, phones, 1)
		phone := phones[0].(map[string]interface{})
		// do_not_call bool must always be emitted (P0-DNC).
		doNotCall, exists := phone["do_not_call"]
		require.True(t, exists, "do_not_call field must always be present")
		assert.Equal(t, true, doNotCall, "do_not_call must be true for DNC phone")
	})

	t.Run("empty contact emits JSON object with no emails or phones arrays", func(t *testing.T) {
		c := &lusha.Contact{}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		out := strings.TrimSpace(buf.String())
		require.NotEmpty(t, out, "should emit one JSON object even when empty")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(out), &obj))
		assert.Equal(t, "lusha", obj["type"])
		_, hasEmails := obj["emails"]
		assert.False(t, hasEmails, "omitempty: emails array must be absent for empty contact")
		_, hasPhones := obj["phones"]
		assert.False(t, hasPhones, "omitempty: phones array must be absent for empty contact")
	})

	t.Run("non-DNC phone has do_not_call false", func(t *testing.T) {
		c := &lusha.Contact{
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0200", Type: "mobile", DoNotCall: false},
			},
		}
		var buf bytes.Buffer
		outputLushaJSONL(&buf, c)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))
		phones := obj["phones"].([]interface{})
		phone := phones[0].(map[string]interface{})
		// do_not_call bool is always emitted — must be false here.
		doNotCall, exists := phone["do_not_call"]
		require.True(t, exists, "do_not_call field must always be emitted")
		assert.Equal(t, false, doNotCall)
	})
}

func TestOutputLushaHuman(t *testing.T) {
	t.Run("renders email and phone rows", func(t *testing.T) {
		c := &lusha.Contact{
			Name:     "Ada Lovelace",
			JobTitle: "Mathematician",
			Company:  "AnalyticalCo",
			Emails: []lusha.EmailEntry{
				{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			},
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-0100", Type: "direct", DoNotCall: false},
			},
		}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "ada@example.com")
		assert.Contains(t, out, "professional")
		assert.Contains(t, out, "+1-555-0100")
		assert.Contains(t, out, "direct")
	})

	t.Run("DNC phone shows DNC marker", func(t *testing.T) {
		c := &lusha.Contact{
			Name: "Eve Example",
			Phones: []lusha.PhoneEntry{
				{Number: "+1-555-9999", Type: "mobile", DoNotCall: true},
			},
		}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "DNC", "DNC phones must display DNC marker")
		assert.Contains(t, out, "+1-555-9999")
	})

	t.Run("empty contact shows no data message", func(t *testing.T) {
		c := &lusha.Contact{}
		var buf bytes.Buffer
		outputLushaHuman(&buf, c, false)
		out := buf.String()
		assert.Contains(t, out, "No contact data returned")
	})
}

// ---------------------------------------------------------------------------
// T104: validateLushaIdentity (reads package-level flag vars directly)
// ---------------------------------------------------------------------------

// resetLushaFlags resets all lusha flag vars to zero values between subtests.
func resetLushaFlags() {
	flagLushaFirstName = ""
	flagLushaLastName = ""
	flagLushaCompany = ""
	flagLushaDomain = ""
	flagLushaEmail = ""
	flagLushaLinkedin = ""
	flagLushaPhone = false
	flagLushaEmailOnly = false
}

func TestValidateLushaIdentity(t *testing.T) {
	tests := []struct {
		name        string
		setup       func()
		wantErr     bool
		errContains string
	}{
		{
			name: "valid name + company",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
				flagLushaCompany = "AnalyticalCo"
			},
			wantErr: false,
		},
		{
			name: "valid name + domain",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
				flagLushaDomain = "analytical.example.com"
			},
			wantErr: false,
		},
		{
			name: "valid email only",
			setup: func() {
				flagLushaEmail = "ada@example.com"
			},
			wantErr: false,
		},
		{
			name: "valid linkedin only",
			setup: func() {
				flagLushaLinkedin = "https://linkedin.com/in/ada"
			},
			wantErr: false,
		},
		{
			name:        "ERROR: no identity set",
			setup:       func() {},
			wantErr:     true,
			errContains: "identity is required",
		},
		{
			name: "ERROR: two identity groups (email + linkedin)",
			setup: func() {
				flagLushaEmail = "ada@example.com"
				flagLushaLinkedin = "https://linkedin.com/in/ada"
			},
			wantErr:     true,
			errContains: "exactly one identity",
		},
		{
			name: "ERROR: name without last name",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaCompany = "AnalyticalCo"
			},
			wantErr:     true,
			errContains: "last-name",
		},
		{
			name: "ERROR: name without company or domain",
			setup: func() {
				flagLushaFirstName = "Ada"
				flagLushaLastName = "Lovelace"
			},
			wantErr:     true,
			errContains: "--company or --domain",
		},
		{
			name: "ERROR: --phone and --email-only together",
			setup: func() {
				flagLushaEmail = "ada@example.com"
				flagLushaPhone = true
				flagLushaEmailOnly = true
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetLushaFlags()
			tc.setup()
			err := validateLushaIdentity()
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveLushaAPIKey(t *testing.T) {
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
			t.Setenv("LUSHA_API_KEY", tc.envValue)
			key, err := resolveLushaAPIKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "LUSHA_API_KEY")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

// TestClassifyLushaError_NoKeyLeak verifies the P0-1 security requirement:
// the sentinel API key value must never appear in any classified error message,
// even if the vendor echoes the key back in the error body (APIError.Details).
func TestClassifyLushaError_NoKeyLeak(t *testing.T) {
	const sentinelKey = "SECRETKEY-DO-NOT-LEAK-abc123"

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "vendor echoes key in 401 Details",
			err:  &lusha.APIError{StatusCode: 401, Details: sentinelKey},
		},
		{
			name: "402 no credits with sentinel",
			err:  &lusha.APIError{StatusCode: 402, Details: sentinelKey},
		},
		{
			name: "403 forbidden",
			err:  &lusha.APIError{StatusCode: 403, Details: "forbidden"},
		},
		{
			name: "429 rate limited",
			err:  &lusha.APIError{StatusCode: 429, Details: "rate limit"},
		},
		{
			name: "404 not found",
			err:  &lusha.APIError{StatusCode: 404, Details: "not found"},
		},
		{
			name: "wrapped 500 with sentinel in Details",
			err:  fmt.Errorf("wrapped: %w", &lusha.APIError{StatusCode: 500, Details: sentinelKey}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyLushaError(tc.err)
			require.Error(t, result)
			out := result.Error()
			// Sentinel key must NEVER appear in any error output (P0-1).
			assert.NotContains(t, out, sentinelKey,
				"classified error must not leak the sentinel API key")
			// Header name must not be echoed either.
			assert.NotContains(t, out, "api_key",
				"classified error must not echo the api_key header name")
		})
	}
}

// TestClassifyLushaError_NetworkWrap verifies that non-*APIError (network/DNS/
// timeout) errors are %w-wrapped by classifyLushaError so errors.Is chains work.
func TestClassifyLushaError_NetworkWrap(t *testing.T) {
	networkErr := errors.New("dial tcp: connection timeout")
	result := classifyLushaError(networkErr)
	require.Error(t, result)
	// The network error must be wrapped (errors.Is unwraps the chain).
	assert.True(t, errors.Is(result, networkErr),
		"classifyLushaError must %w-wrap non-*APIError so errors.Is works")
	// The error message must contain the original cause for debuggability.
	assert.Contains(t, result.Error(), "timeout")
}

// ---------------------------------------------------------------------------
// T105: Command registration
// ---------------------------------------------------------------------------

func TestEnumLushaRegistered(t *testing.T) {
	// 1. enumCmd must have a "passive" subcommand.
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	// 2. The canonical "lusha" command must live under passive.
	var canonicalLusha *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "lusha" {
			canonicalLusha = cmd
			break
		}
	}
	require.NotNil(t, canonicalLusha, `"lusha" must be a subcommand of enumPassiveCmd`)

	// Verify expected flags on the canonical command.
	for _, name := range []string{
		"first-name", "last-name", "company", "domain",
		"email", "linkedin", "phone", "email-only", "api-key",
	} {
		require.NotNilf(t, canonicalLusha.Flags().Lookup(name),
			"--%s flag must exist on canonical lusha", name)
	}

	// --domain must NOT be marked required (identity validated in RunE).
	domainFlag := canonicalLusha.Flags().Lookup("domain")
	require.NotNil(t, domainFlag)
	_, isRequired := domainFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.False(t, isRequired, "--domain must NOT be marked as required for lusha")

	// 3. A hidden back-compat alias must exist directly under enumCmd.
	var alias *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "lusha" {
			alias = cmd
			break
		}
	}
	require.NotNil(t, alias, `hidden "lusha" alias must be registered directly under enumCmd`)
	assert.True(t, alias.Hidden, "back-compat lusha alias must be Hidden")
	assert.NotEmpty(t, alias.Deprecated, "back-compat lusha alias must be Deprecated")
}
