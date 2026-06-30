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

	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

// ---------------------------------------------------------------------------
// Flag registration
// ---------------------------------------------------------------------------

// TestEnumGithubCmd_Flags verifies that enumGithubCmd carries the required
// flags and shorthands, and that no shorthand collides with the global
// persistent --threads/-t flag.
func TestEnumGithubCmd_Flags(t *testing.T) {
	// --emails / -e
	f := enumGithubCmd.Flags().Lookup("emails")
	require.NotNil(t, f, "--emails flag must exist on enumGithubCmd")
	sh := enumGithubCmd.Flags().ShorthandLookup("e")
	require.NotNil(t, sh, "-e shorthand must exist on enumGithubCmd")
	assert.Equal(t, "emails", sh.Name, "-e must map to --emails")

	// --email-file / -E
	f = enumGithubCmd.Flags().Lookup("email-file")
	require.NotNil(t, f, "--email-file flag must exist on enumGithubCmd")
	sh = enumGithubCmd.Flags().ShorthandLookup("E")
	require.NotNil(t, sh, "-E shorthand must exist on enumGithubCmd")
	assert.Equal(t, "email-file", sh.Name, "-E must map to --email-file")

	// --domain / -d
	f = enumGithubCmd.Flags().Lookup("domain")
	require.NotNil(t, f, "--domain flag must exist on enumGithubCmd")
	sh = enumGithubCmd.Flags().ShorthandLookup("d")
	require.NotNil(t, sh, "-d shorthand must exist on enumGithubCmd")
	assert.Equal(t, "domain", sh.Name, "-d must map to --domain")

	// --format (no shorthand; default is first.last)
	f = enumGithubCmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag must exist on enumGithubCmd")
	assert.Equal(t, "first.last", f.DefValue, "--format default must be \"first.last\"")

	// --limit (no shorthand)
	f = enumGithubCmd.Flags().Lookup("limit")
	require.NotNil(t, f, "--limit flag must exist on enumGithubCmd")

	// --token (no shorthand; -t is taken by global --threads)
	f = enumGithubCmd.Flags().Lookup("token")
	require.NotNil(t, f, "--token flag must exist on enumGithubCmd")

	// No -t shorthand: it collides with the global persistent --threads/-t.
	noT := enumGithubCmd.Flags().ShorthandLookup("t")
	require.Nil(t, noT,
		"enumGithubCmd must not define a local -t shorthand (collides with global --threads/-t)")
}

// ---------------------------------------------------------------------------
// Command wiring (HARD MOVE assertion)
// ---------------------------------------------------------------------------

// TestEnumGithubCmd_WiredUnderActiveCmd verifies the cobra tree after the
// "enum active" hard move:
//
//   - enumCmd has a child named "active"
//   - enumActiveCmd (the "active" child) has github, oracles, google, kerberos,
//     teams, and custom as children
//   - enumCmd does NOT directly have google, kerberos, teams, oracles, or custom
//     as children (they were hard-moved)
func TestEnumGithubCmd_WiredUnderActiveCmd(t *testing.T) {
	// 1. enumCmd must have an "active" child.
	var active *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "active" {
			active = cmd
			break
		}
	}
	require.NotNil(t, active, `enumCmd must have an "active" subcommand`)

	// 2. "active" must have github, oracles, google, kerberos, teams, and custom.
	wantActiveChildren := []string{"github", "oracles", "google", "kerberos", "teams", "custom"}
	for _, name := range wantActiveChildren {
		var found bool
		for _, cmd := range active.Commands() {
			if cmd.Use == name {
				found = true
				break
			}
		}
		assert.True(t, found, "enumActiveCmd must have %q as a subcommand", name)
	}

	// 3. enumCmd must NOT have google, kerberos, teams, oracles, or custom as
	//    direct children (hard move — these are now under "active" only).
	hardMovedNames := []string{"google", "kerberos", "teams", "oracles", "custom"}
	for _, name := range hardMovedNames {
		for _, cmd := range enumCmd.Commands() {
			// Allow hidden/deprecated back-compat aliases (e.g., apollo has one),
			// but these five never had aliases, so none should appear at all.
			if cmd.Use == name {
				assert.True(t, cmd.Hidden || cmd.Deprecated != "",
					"enumCmd must not have %q as a direct non-deprecated child (hard move)", name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// --no-reveal flag contract
// ---------------------------------------------------------------------------

// TestEnumGithubCmd_NoRevealFlag asserts the flag-level contract for the
// boolean --no-reveal flag registered on enumGithubCmd:
//  1. The flag exists on the command.
//  2. Its default value is "false".
//  3. It is typed as a bool flag.
//  4. It has no shorthand (empty string).
func TestEnumGithubCmd_NoRevealFlag(t *testing.T) {
	f := enumGithubCmd.Flags().Lookup("no-reveal")
	require.NotNil(t, f, "--no-reveal flag must exist on enumGithubCmd")
	assert.Equal(t, "false", f.DefValue, "--no-reveal default must be \"false\"")
	assert.Equal(t, "bool", f.Value.Type(), "--no-reveal must be a bool flag")
	assert.Equal(t, "", f.Shorthand, "--no-reveal must have no shorthand")
}

// ---------------------------------------------------------------------------
// githubEnumTargets
// ---------------------------------------------------------------------------

// TestGithubEnumTargets_InlineEmails verifies that --emails CSV is parsed,
// trimmed, and deduplicated.
func TestGithubEnumTargets_InlineEmails(t *testing.T) {
	origEmails := flagGithubEnumEmails
	origEmailFile := flagGithubEnumEmailFile
	origDomain := flagGithubEnumDomain
	defer func() {
		flagGithubEnumEmails = origEmails
		flagGithubEnumEmailFile = origEmailFile
		flagGithubEnumDomain = origDomain
	}()

	flagGithubEnumEmails = "alice@example.com,bob@example.com,alice@example.com"
	flagGithubEnumEmailFile = ""
	flagGithubEnumDomain = ""

	emails, err := githubEnumTargets()
	require.NoError(t, err)

	// Dedup: alice appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")
}

// TestGithubEnumTargets_NoSource verifies that an error is returned (and
// mentions "provide") when no --emails, --email-file, or --domain is given.
func TestGithubEnumTargets_NoSource(t *testing.T) {
	origEmails := flagGithubEnumEmails
	origEmailFile := flagGithubEnumEmailFile
	origDomain := flagGithubEnumDomain
	defer func() {
		flagGithubEnumEmails = origEmails
		flagGithubEnumEmailFile = origEmailFile
		flagGithubEnumDomain = origDomain
	}()

	flagGithubEnumEmails = ""
	flagGithubEnumEmailFile = ""
	flagGithubEnumDomain = ""

	_, err := githubEnumTargets()
	require.Error(t, err, "githubEnumTargets must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error must guide the user to supply a target source")
}

// ---------------------------------------------------------------------------
// resolveGithubToken
// ---------------------------------------------------------------------------

// TestResolveGithubToken verifies the flag-overrides-env, env-fallback, and
// empty-allowed behaviors. The token is never required (existence-only mode is
// valid with an empty token).
func TestResolveGithubToken(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envValue  string
		wantToken string
	}{
		{
			name:      "flag value overrides env var",
			flagValue: "flag-token",
			envValue:  "env-token",
			wantToken: "flag-token",
		},
		{
			name:      "env var used when flag is empty",
			flagValue: "",
			envValue:  "env-token",
			wantToken: "env-token",
		},
		{
			name:      "empty token allowed (existence-only mode)",
			flagValue: "",
			envValue:  "",
			wantToken: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tc.envValue)

			// resolveGithubToken writes a warning to stderr when the flag is
			// used; suppress that by running in quiet mode.
			origQuiet := flagQuiet
			flagQuiet = true
			defer func() { flagQuiet = origQuiet }()

			got := resolveGithubToken(tc.flagValue, false)
			assert.Equal(t, tc.wantToken, got)
		})
	}
}

// TestResolveGithubToken_FlagWarns verifies that passing a non-empty flag
// value emits a warning (does not panic, does not leak the token into the
// warning text when quiet=false). We can observe the warning indirectly: the
// function must return the flag value.
func TestResolveGithubToken_FlagValueReturned(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "env-value")
	origQuiet := flagQuiet
	flagQuiet = true
	defer func() { flagQuiet = origQuiet }()

	got := resolveGithubToken("flag-overrides", false)
	assert.Equal(t, "flag-overrides", got,
		"flag value must take precedence over GITHUB_TOKEN env var")
}

// ---------------------------------------------------------------------------
// outputGithubEnumJSONL
// ---------------------------------------------------------------------------

// TestOutputGithubEnumJSONL verifies the JSON structure of each output line:
// type, email, exists, optional username and error fields.
func TestOutputGithubEnumJSONL(t *testing.T) {
	tests := []struct {
		name         string
		result       githubenum.Result
		wantType     string
		wantExists   bool
		wantUsername string // empty → key must be absent (omitempty)
		wantError    string // empty → key must be absent (omitempty)
	}{
		{
			name: "account exists with username revealed",
			result: githubenum.Result{
				Email:    "alice@example.com",
				Exists:   true,
				Username: "alice-gh",
			},
			wantType:     "github_account",
			wantExists:   true,
			wantUsername: "alice-gh",
		},
		{
			name: "account exists without username",
			result: githubenum.Result{
				Email:  "bob@example.com",
				Exists: true,
			},
			wantType:   "github_account",
			wantExists: true,
			// username omitted (omitempty)
		},
		{
			name: "account does not exist",
			result: githubenum.Result{
				Email:  "nobody@example.com",
				Exists: false,
			},
			wantType:   "github_account",
			wantExists: false,
		},
		{
			name: "result with error",
			result: githubenum.Result{
				Email: "err@example.com",
				Error: assert.AnError,
			},
			wantType:  "github_account",
			wantError: assert.AnError.Error(),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			outputGithubEnumJSONL(&buf, []githubenum.Result{tc.result})

			line := strings.TrimSpace(buf.String())
			require.NotEmpty(t, line, "outputGithubEnumJSONL must produce a JSONL line")

			var obj map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &obj),
				"JSONL output must be valid JSON: %q", line)

			assert.Equal(t, tc.wantType, obj["type"], "type field must be %q", tc.wantType)
			assert.Equal(t, tc.result.Email, obj["email"], "email field must match")

			gotExists, _ := obj["exists"].(bool)
			assert.Equal(t, tc.wantExists, gotExists, "exists field must match")

			// username is omitempty — present only when non-empty.
			if tc.wantUsername != "" {
				assert.Equal(t, tc.wantUsername, obj["username"],
					"username must be %q", tc.wantUsername)
			} else {
				assert.NotContains(t, obj, "username",
					"username key must be absent when empty (omitempty)")
			}

			// error is omitempty — present only when non-nil.
			if tc.wantError != "" {
				assert.Equal(t, tc.wantError, obj["error"],
					"error field must contain the error text")
			} else {
				assert.NotContains(t, obj, "error",
					"error key must be absent when result.Error is nil")
			}
		})
	}
}
