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

	"github.com/praetorian-inc/brutus/pkg/enum/google"
)

// ---------------------------------------------------------------------------
// TestEnumGoogleCmd_Flags
// Verifies that all documented flags exist on enumGoogleCmd and that
// no shorthand collides with the global --threads/-t flag.
// ---------------------------------------------------------------------------

func TestEnumGoogleCmd_Flags(t *testing.T) {
	// --emails / -e
	f := enumGoogleCmd.Flags().Lookup("emails")
	require.NotNil(t, f, "--emails flag must exist on enumGoogleCmd")
	sh := enumGoogleCmd.Flags().ShorthandLookup("e")
	require.NotNil(t, sh, "-e shorthand must exist on enumGoogleCmd")
	assert.Equal(t, "emails", sh.Name, "-e must map to --emails")

	// --email-file / -E
	f = enumGoogleCmd.Flags().Lookup("email-file")
	require.NotNil(t, f, "--email-file flag must exist on enumGoogleCmd")
	sh = enumGoogleCmd.Flags().ShorthandLookup("E")
	require.NotNil(t, sh, "-E shorthand must exist on enumGoogleCmd")
	assert.Equal(t, "email-file", sh.Name, "-E must map to --email-file")

	// --domain / -d
	f = enumGoogleCmd.Flags().Lookup("domain")
	require.NotNil(t, f, "--domain flag must exist on enumGoogleCmd")
	sh = enumGoogleCmd.Flags().ShorthandLookup("d")
	require.NotNil(t, sh, "-d shorthand must exist on enumGoogleCmd")
	assert.Equal(t, "domain", sh.Name, "-d must map to --domain")

	// --format (no shorthand required; default is first.last)
	f = enumGoogleCmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag must exist on enumGoogleCmd")
	assert.Equal(t, "first.last", f.DefValue, "--format default must be \"first.last\"")

	// --limit (no shorthand required)
	f = enumGoogleCmd.Flags().Lookup("limit")
	require.NotNil(t, f, "--limit flag must exist on enumGoogleCmd")

	// No -t shorthand: collides with global persistent --threads/-t.
	noT := enumGoogleCmd.Flags().ShorthandLookup("t")
	require.Nil(t, noT,
		"enumGoogleCmd must not define a local -t shorthand (collides with global --threads/-t)")

	// No -s shorthand (consistent with the pattern used by other enum subcommands).
	noS := enumGoogleCmd.Flags().ShorthandLookup("s")
	require.Nil(t, noS,
		"enumGoogleCmd must not define a local -s shorthand (reserved)")
}

// TestEnumGoogleCmd_RegisteredUnderActiveCmd verifies that enumGoogleCmd has
// Use=="google" and is a child of enumActiveCmd (hard move — it is no longer
// a direct child of enumCmd).
func TestEnumGoogleCmd_RegisteredUnderActiveCmd(t *testing.T) {
	assert.Equal(t, "google", enumGoogleCmd.Use,
		"enumGoogleCmd.Use must be \"google\"")

	var found bool
	for _, cmd := range enumActiveCmd.Commands() {
		if cmd.Use == "google" {
			found = true
			break
		}
	}
	assert.True(t, found, "enumGoogleCmd must be registered as a subcommand of enumActiveCmd (hard move)")
}

// ---------------------------------------------------------------------------
// TestOutputGoogleEnumJSONL
// Feeds google.Result values and asserts the type/method/idp fields.
// ---------------------------------------------------------------------------

func TestOutputGoogleEnumJSONL(t *testing.T) {
	tests := []struct {
		name       string
		result     google.Result
		wantType   string
		wantExists bool
		wantMethod string // empty means key must be absent (omitempty)
		wantIdP    string // empty means key must be absent (omitempty)
	}{
		{
			name: "workspace-sso with IdP",
			result: google.Result{
				Email:  "sso@example.com",
				Exists: true,
				Method: google.MethodWorkspaceSSO,
				IdP:    "login.okta.com",
			},
			wantType:   "google_account",
			wantExists: true,
			wantMethod: "workspace-sso",
			wantIdP:    "login.okta.com",
		},
		{
			name: "gmail method",
			result: google.Result{
				Email:  "gm@gmail.com",
				Exists: true,
				Method: google.MethodGmail,
			},
			wantType:   "google_account",
			wantExists: true,
			wantMethod: "gmail",
			wantIdP:    "", // absent (omitempty)
		},
		{
			name: "not found — method and idp omitted",
			result: google.Result{
				Email:  "nobody@example.com",
				Exists: false,
				Method: google.MethodNone,
			},
			wantType:   "google_account",
			wantExists: false,
			wantMethod: "", // absent (omitempty — MethodNone is "")
			wantIdP:    "", // absent
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputGoogleEnumJSONL(&buf, []google.Result{tc.result})

			line := strings.TrimSpace(buf.String())
			require.NotEmpty(t, line, "outputGoogleEnumJSONL must produce a JSONL line")

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

			// method is omitempty — when MethodNone (""), the key must be absent.
			if tc.wantMethod != "" {
				assert.Equal(t, tc.wantMethod, obj["method"],
					"method field must be %q", tc.wantMethod)
			} else {
				assert.NotContains(t, obj, "method",
					"method key must be absent when MethodNone (omitempty)")
			}

			// idp is omitempty — absent when empty string.
			if tc.wantIdP != "" {
				assert.Equal(t, tc.wantIdP, obj["idp"],
					"idp field must be %q", tc.wantIdP)
			} else {
				assert.NotContains(t, obj, "idp",
					"idp key must be absent when empty (omitempty)")
			}

			// error must be absent when result.Error is nil.
			assert.NotContains(t, obj, "error",
				"error key must be absent when result.Error is nil")
		})
	}
}

// ---------------------------------------------------------------------------
// TestOutputGoogleEnumResultLine
// Verifies human-readable line output for EXISTS, gmail, and ANSI safety.
// ---------------------------------------------------------------------------

func TestOutputGoogleEnumResultLine(t *testing.T) {
	t.Run("workspace-sso with IdP shows EXISTS and IdP", func(t *testing.T) {
		r := google.Result{
			Email:  "user@example.com",
			Exists: true,
			Method: google.MethodWorkspaceSSO,
			IdP:    "login.okta.com",
		}
		var buf bytes.Buffer
		outputGoogleEnumResultLine(&buf, r, false /* useColor */)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"workspace-sso EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "workspace-sso",
			"workspace-sso result must mention the method")
		assert.Contains(t, out, "login.okta.com",
			"workspace-sso result must contain the IdP host")
	})

	t.Run("gmail method shows gmail", func(t *testing.T) {
		r := google.Result{
			Email:  "user@gmail.com",
			Exists: true,
			Method: google.MethodGmail,
		}
		var buf bytes.Buffer
		outputGoogleEnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "EXISTS",
			"gmail EXISTS result must contain \"EXISTS\"")
		assert.Contains(t, out, "gmail",
			"gmail result must mention the method")
		assert.NotContains(t, out, "workspace-sso",
			"gmail result must not mention workspace-sso")
	})

	t.Run("not found shows not found label", func(t *testing.T) {
		r := google.Result{
			Email:  "nobody@example.com",
			Exists: false,
		}
		var buf bytes.Buffer
		outputGoogleEnumResultLine(&buf, r, false)
		out := buf.String()

		assert.Contains(t, out, "not found",
			"not-found result must contain \"not found\"")
		assert.NotContains(t, out, "EXISTS",
			"not-found result must not contain \"EXISTS\"")
	})

	t.Run("malicious IdP with ANSI escape is sanitized", func(t *testing.T) {
		// A server-controlled IdP that injects a raw ESC (0x1B) byte. The output
		// layer must strip it before rendering (P0-4 requirement).
		maliciousIdP := "login.okta.com\x1b[31mINJECTED\x1b[0m"
		r := google.Result{
			Email:  "user@example.com",
			Exists: true,
			Method: google.MethodWorkspaceSSO,
			IdP:    maliciousIdP,
		}
		var buf bytes.Buffer
		outputGoogleEnumResultLine(&buf, r, false)
		out := buf.String()

		// Raw ESC byte must not appear in the output.
		assert.NotContains(t, out, "\x1b",
			"raw ESC byte (0x1B) must be absent from the rendered line (sanitizeTerminal must strip it)")
	})
}

// ---------------------------------------------------------------------------
// TestGoogleEnumTargets
// Exercises googleEnumTargets() using the file-local flag variables directly,
// saving and restoring them with defer.
// ---------------------------------------------------------------------------

func TestGoogleEnumTargets_InlineEmails(t *testing.T) {
	// Save and restore flag globals.
	origEmails := flagGoogleEnumEmails
	origEmailFile := flagGoogleEnumEmailFile
	origDomain := flagGoogleEnumDomain
	defer func() {
		flagGoogleEnumEmails = origEmails
		flagGoogleEnumEmailFile = origEmailFile
		flagGoogleEnumDomain = origDomain
	}()

	flagGoogleEnumEmails = "alice@example.com,bob@example.com,alice@example.com"
	flagGoogleEnumEmailFile = ""
	flagGoogleEnumDomain = ""

	emails, err := googleEnumTargets()
	require.NoError(t, err)

	// Deduplication: alice@example.com appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")
}

func TestGoogleEnumTargets_NoSource(t *testing.T) {
	origEmails := flagGoogleEnumEmails
	origEmailFile := flagGoogleEnumEmailFile
	origDomain := flagGoogleEnumDomain
	defer func() {
		flagGoogleEnumEmails = origEmails
		flagGoogleEnumEmailFile = origEmailFile
		flagGoogleEnumDomain = origDomain
	}()

	flagGoogleEnumEmails = ""
	flagGoogleEnumEmailFile = ""
	flagGoogleEnumDomain = ""

	_, err := googleEnumTargets()
	require.Error(t, err, "googleEnumTargets must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error message must guide the user to supply a target source")
}
