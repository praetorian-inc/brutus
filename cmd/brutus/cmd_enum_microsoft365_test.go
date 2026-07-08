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

	m365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

// ---------------------------------------------------------------------------
// TestEnumMicrosoft365Cmd_Flags
// Verifies that all documented flags exist on enumMicrosoft365Cmd and that
// no shorthand collides with the global --threads/-t flag.
// ---------------------------------------------------------------------------

func TestEnumMicrosoft365Cmd_Flags(t *testing.T) {
	// --emails / -e
	f := enumMicrosoft365Cmd.Flags().Lookup("emails")
	require.NotNil(t, f, "--emails flag must exist on enumMicrosoft365Cmd")
	sh := enumMicrosoft365Cmd.Flags().ShorthandLookup("e")
	require.NotNil(t, sh, "-e shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "emails", sh.Name, "-e must map to --emails")

	// --email-file / -E
	f = enumMicrosoft365Cmd.Flags().Lookup("email-file")
	require.NotNil(t, f, "--email-file flag must exist on enumMicrosoft365Cmd")
	sh = enumMicrosoft365Cmd.Flags().ShorthandLookup("E")
	require.NotNil(t, sh, "-E shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "email-file", sh.Name, "-E must map to --email-file")

	// --domain / -d
	f = enumMicrosoft365Cmd.Flags().Lookup("domain")
	require.NotNil(t, f, "--domain flag must exist on enumMicrosoft365Cmd")
	sh = enumMicrosoft365Cmd.Flags().ShorthandLookup("d")
	require.NotNil(t, sh, "-d shorthand must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "domain", sh.Name, "-d must map to --domain")

	// --format (no shorthand required; default is first.last)
	f = enumMicrosoft365Cmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag must exist on enumMicrosoft365Cmd")
	assert.Equal(t, "first.last", f.DefValue, "--format default must be \"first.last\"")

	// --limit (no shorthand required)
	f = enumMicrosoft365Cmd.Flags().Lookup("limit")
	require.NotNil(t, f, "--limit flag must exist on enumMicrosoft365Cmd")

	// No -t shorthand: collides with global persistent --threads/-t.
	noT := enumMicrosoft365Cmd.Flags().ShorthandLookup("t")
	require.Nil(t, noT,
		"enumMicrosoft365Cmd must not define a local -t shorthand (collides with global --threads/-t)")

	// No -s shorthand (consistent with the pattern used by other enum subcommands).
	noS := enumMicrosoft365Cmd.Flags().ShorthandLookup("s")
	require.Nil(t, noS,
		"enumMicrosoft365Cmd must not define a local -s shorthand (reserved)")
}

// TestEnumMicrosoft365Cmd_RegisteredUnderActiveCmd verifies that
// enumMicrosoft365Cmd has Use=="microsoft365" and is a child of enumActiveCmd.
func TestEnumMicrosoft365Cmd_RegisteredUnderActiveCmd(t *testing.T) {
	assert.Equal(t, "microsoft365", enumMicrosoft365Cmd.Use,
		"enumMicrosoft365Cmd.Use must be \"microsoft365\"")

	var found bool
	for _, cmd := range enumActiveCmd.Commands() {
		if cmd.Use == "microsoft365" {
			found = true
			break
		}
	}
	assert.True(t, found, "enumMicrosoft365Cmd must be registered as a subcommand of enumActiveCmd")
}

// ---------------------------------------------------------------------------
// TestOutputMicrosoft365EnumJSONL
// Feeds m365.Result values and asserts the type/if_exists_result/federation
// fields, including omitempty behavior.
// ---------------------------------------------------------------------------

func TestOutputMicrosoft365EnumJSONL(t *testing.T) {
	tests := []struct {
		name              string
		result            m365.Result
		wantType          string
		wantExists        bool
		wantIfExists      int
		wantFederated     bool   // false means key must be absent (omitempty)
		wantFederationURL string // empty means key must be absent (omitempty)
	}{
		{
			name: "managed exists",
			result: m365.Result{
				Email:          "managed@example.com",
				Exists:         true,
				IfExistsResult: m365.IfExistsResultExists,
				Federated:      false,
			},
			wantType:          "microsoft365_account",
			wantExists:        true,
			wantIfExists:      0,
			wantFederated:     false, // absent (omitempty)
			wantFederationURL: "",    // absent (omitempty)
		},
		{
			name: "federated different tenant",
			result: m365.Result{
				Email:          "fed@example.com",
				Exists:         true,
				IfExistsResult: m365.IfExistsResultDifferentTenant,
				Federated:      true,
				FederationURL:  "https://login.okta.com/x",
			},
			wantType:          "microsoft365_account",
			wantExists:        true,
			wantIfExists:      5,
			wantFederated:     true,
			wantFederationURL: "https://login.okta.com/x",
		},
		{
			name: "not found",
			result: m365.Result{
				Email:          "nobody@example.com",
				Exists:         false,
				IfExistsResult: m365.IfExistsResultNotExists,
			},
			wantType:          "microsoft365_account",
			wantExists:        false,
			wantIfExists:      1,
			wantFederated:     false,
			wantFederationURL: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputMicrosoft365EnumJSONL(&buf, []m365.Result{tc.result})

			line := strings.TrimSpace(buf.String())
			require.NotEmpty(t, line, "outputMicrosoft365EnumJSONL must produce a JSONL line")

			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj),
				"JSONL output must be valid JSON: %q", line)

			assert.Equal(t, tc.wantType, obj["type"],
				"type field must be %q", tc.wantType)

			assert.Equal(t, tc.result.Email, obj["email"],
				"email field must match result.Email")

			wantExists, _ := obj["exists"].(bool)
			assert.Equal(t, tc.wantExists, wantExists,
				"exists field must match result.Exists")

			// if_exists_result is NOT omitempty — 0 is a valid, common value and
			// must always be present.
			require.Contains(t, obj, "if_exists_result",
				"if_exists_result must always be present (not omitempty)")
			gotIfExists, ok := obj["if_exists_result"].(float64)
			require.True(t, ok, "if_exists_result must be numeric")
			assert.Equal(t, tc.wantIfExists, int(gotIfExists),
				"if_exists_result must be %d", tc.wantIfExists)

			// federated is omitempty — absent when false.
			if tc.wantFederated {
				assert.Equal(t, true, obj["federated"],
					"federated field must be true")
			} else {
				assert.NotContains(t, obj, "federated",
					"federated key must be absent when false (omitempty)")
			}

			// federation_url is omitempty — absent when empty.
			if tc.wantFederationURL != "" {
				assert.Equal(t, tc.wantFederationURL, obj["federation_url"],
					"federation_url field must be %q", tc.wantFederationURL)
			} else {
				assert.NotContains(t, obj, "federation_url",
					"federation_url key must be absent when empty (omitempty)")
			}

			// error must be absent when result.Error is nil.
			assert.NotContains(t, obj, "error",
				"error key must be absent when result.Error is nil")
		})
	}

	// Error row: if_exists_result must be omitted (no API code was decoded),
	// and the error key must be present with the error text.
	t.Run("error omits if_exists_result", func(t *testing.T) {
		result := m365.Result{
			Email:  "boom@example.com",
			Error:  errors.New("throttled"),
			Exists: false,
		}

		var buf bytes.Buffer
		outputMicrosoft365EnumJSONL(&buf, []m365.Result{result})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputMicrosoft365EnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		wantExists, _ := obj["exists"].(bool)
		assert.False(t, wantExists, "exists field must be false")

		assert.Contains(t, obj, "error", "error key must be present on an error row")
		assert.Equal(t, "throttled", obj["error"], "error field must contain the error message")

		assert.NotContains(t, obj, "if_exists_result",
			"if_exists_result must be omitted on an error row (no API code was decoded)")
	})
}

// ---------------------------------------------------------------------------
// TestOutputMicrosoft365EnumResultLine
// Verifies human-readable line output for EXISTS, federation, and ANSI safety.
// ---------------------------------------------------------------------------

func TestOutputMicrosoft365EnumResultLine(t *testing.T) {
	t.Run("managed exists shows EXISTS and managed", func(t *testing.T) {
		r := m365.Result{
			Email:          "managed@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultExists,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false /* useColor */)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"managed EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "managed",
			"managed result must mention the tenant relationship")
	})

	t.Run("different-tenant federated shows EXISTS, tenant, IdP host", func(t *testing.T) {
		r := m365.Result{
			Email:          "fed@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultDifferentTenant,
			Federated:      true,
			FederationURL:  "https://login.okta.com/x",
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"federated EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "different tenant",
			"result must mention the different-tenant relationship")
		assert.Contains(t, out, "federated",
			"result must mention federation")
		assert.Contains(t, out, "login.okta.com",
			"result must contain the federation IdP host")
	})

	t.Run("not found shows not found label", func(t *testing.T) {
		r := m365.Result{
			Email:          "nobody@example.com",
			Exists:         false,
			IfExistsResult: m365.IfExistsResultNotExists,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "not found",
			"not-found result must contain \"not found\"")
		assert.NotContains(t, out, "EXISTS",
			"not-found result must not contain \"EXISTS\"")
	})

	t.Run("error row renders as an error, not not-found", func(t *testing.T) {
		r := m365.Result{
			Email:          "boom@example.com",
			Error:          errors.New("request failed: timeout"),
			Exists:         false,
			IfExistsResult: 0,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "error",
			"error result must contain \"error\"")
		assert.Contains(t, out, "timeout",
			"error result must contain the underlying error message")
		assert.NotContains(t, out, "not found",
			"error result must not be rendered as \"not found\"")
		assert.NotContains(t, out, "EXISTS",
			"error result must not be rendered as \"EXISTS\"")
	})

	t.Run("error message with ANSI escape is sanitized", func(t *testing.T) {
		// The error message may embed server-controlled or otherwise unsafe
		// text; a raw ESC (0x1B) byte must be stripped before rendering
		// (sanitizeTerminal, P0-4 requirement).
		r := m365.Result{
			Email:  "boom@example.com",
			Error:  errors.New("bad \x1b[31mX\x1b[0m"),
			Exists: false,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		assert.NotContains(t, out, "\x1b",
			"raw ESC byte (0x1B) in an error message must be absent from the rendered line")
	})

	t.Run("malicious FederationURL with ANSI escape is sanitized", func(t *testing.T) {
		// A server-controlled FederationURL that injects a raw ESC (0x1B) byte.
		// The output layer must strip it before rendering (P0-4 requirement).
		maliciousURL := "https://okta.com\x1b[31mX\x1b[0m"
		r := m365.Result{
			Email:          "user@example.com",
			Exists:         true,
			IfExistsResult: m365.IfExistsResultDifferentTenant,
			Federated:      true,
			FederationURL:  maliciousURL,
		}
		var buf bytes.Buffer
		outputMicrosoft365EnumResultLine(&buf, r, false)
		out := buf.String()

		// Raw ESC byte must not appear in the output.
		assert.NotContains(t, out, "\x1b",
			"raw ESC byte (0x1B) must be absent from the rendered line (sanitizeTerminal must strip it)")
	})
}

// ---------------------------------------------------------------------------
// TestMicrosoft365EnumTargets
// Exercises microsoft365EnumTargets() using the file-local flag variables
// directly, saving and restoring them with defer.
// ---------------------------------------------------------------------------

func TestMicrosoft365EnumTargets_InlineEmails(t *testing.T) {
	// Save and restore flag globals.
	origEmails := flagM365EnumEmails
	origEmailFile := flagM365EnumEmailFile
	origDomain := flagM365EnumDomain
	defer func() {
		flagM365EnumEmails = origEmails
		flagM365EnumEmailFile = origEmailFile
		flagM365EnumDomain = origDomain
	}()

	flagM365EnumEmails = "alice@example.com,bob@example.com,alice@example.com"
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	emails, err := microsoft365EnumTargets()
	require.NoError(t, err)

	// Deduplication: alice@example.com appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")
}

func TestMicrosoft365EnumTargets_NoSource(t *testing.T) {
	origEmails := flagM365EnumEmails
	origEmailFile := flagM365EnumEmailFile
	origDomain := flagM365EnumDomain
	defer func() {
		flagM365EnumEmails = origEmails
		flagM365EnumEmailFile = origEmailFile
		flagM365EnumDomain = origDomain
	}()

	flagM365EnumEmails = ""
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	_, err := microsoft365EnumTargets()
	require.Error(t, err, "microsoft365EnumTargets must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error message must guide the user to supply a target source")
}

// TestMicrosoft365EnumTargets_CaseInsensitiveDedup verifies that dedup keys on
// the lowercased email (the GetCredentialType API is case-insensitive) while
// preserving the first-seen casing in the returned results.
func TestMicrosoft365EnumTargets_CaseInsensitiveDedup(t *testing.T) {
	origEmails := flagM365EnumEmails
	origEmailFile := flagM365EnumEmailFile
	origDomain := flagM365EnumDomain
	defer func() {
		flagM365EnumEmails = origEmails
		flagM365EnumEmailFile = origEmailFile
		flagM365EnumDomain = origDomain
	}()

	flagM365EnumEmails = "Alice@Example.com,alice@example.com,BOB@example.com"
	flagM365EnumEmailFile = ""
	flagM365EnumDomain = ""

	emails, err := microsoft365EnumTargets()
	require.NoError(t, err)

	// Case-variant duplicates collapse: "Alice@Example.com" and
	// "alice@example.com" are the same target.
	assert.Len(t, emails, 2, "case-variant duplicates must collapse")

	// The first-seen original casing must be preserved, not a lowercased form.
	assert.Contains(t, emails, "Alice@Example.com",
		"first-seen casing must be preserved")
	assert.NotContains(t, emails, "alice@example.com",
		"the later-seen lowercase duplicate must not also appear")
	assert.Contains(t, emails, "BOB@example.com")
}
