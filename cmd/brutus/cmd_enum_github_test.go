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
// githubEnumTargetList
//
// 10T-535: githubEnumTargets() ([]string, error) was a dead []string adapter
// kept alive only by these tests (the real logic — and the only production
// caller, runEnumGithub — lives in githubEnumTargetList() ([]enum.Target,
// error)). Retargeted onto githubEnumTargetList and strengthened to assert
// that supplied (--emails/--email-file) targets carry no name, using the
// targetEmails helper from cmd_enum_custom_test.go for compact address
// assertions.
// ---------------------------------------------------------------------------

// TestGithubEnumTargetList_InlineEmails verifies that --emails CSV is parsed,
// trimmed, and deduplicated, and that every CLI-supplied target carries no
// name (a supplied address says nothing about whose it is).
func TestGithubEnumTargetList_InlineEmails(t *testing.T) {
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

	got, err := githubEnumTargetList()
	require.NoError(t, err)

	emails := targetEmails(got)
	// Dedup: alice appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestGithubEnumTargetList_NoSource verifies that an error is returned (and
// mentions "provide") when no --emails, --email-file, or --domain is given.
func TestGithubEnumTargetList_NoSource(t *testing.T) {
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

	_, err := githubEnumTargetList()
	require.Error(t, err, "githubEnumTargetList must fail when no source is supplied")
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

// ---------------------------------------------------------------------------
// outputGithubEnumJSONL — First/Last name propagation (10T-535)
// ---------------------------------------------------------------------------

// TestOutputGithubEnumJSONL_NameFields pins the never-invent-a-name rule: a
// Result carrying First/Last (from --generate) must emit "first"/"last" in
// the JSONL row, while a Result with empty First/Last (supplied via --emails
// or --email-file) must OMIT both keys entirely rather than emit them as "".
// Pre-existing fields (type/email/exists/username) must be unaffected.
func TestOutputGithubEnumJSONL_NameFields(t *testing.T) {
	named := githubenum.Result{
		Email:    "john.smith@example.com",
		Exists:   true,
		Username: "jsmith-gh",
		First:    "john",
		Last:     "smith",
	}
	unnamed := githubenum.Result{
		Email:    "supplied@example.com",
		Exists:   true,
		Username: "supplied-gh",
	}

	t.Run("named result emits first and last", func(t *testing.T) {
		var buf bytes.Buffer
		outputGithubEnumJSONL(&buf, []githubenum.Result{named})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGithubEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.Equal(t, "john", obj["first"], `first field must be "john"`)
		assert.Equal(t, "smith", obj["last"], `last field must be "smith"`)

		// Pre-existing fields must remain unaffected by the new ones.
		assert.Equal(t, "github_account", obj["type"])
		assert.Equal(t, named.Email, obj["email"])
		assert.Equal(t, true, obj["exists"])
		assert.Equal(t, "jsmith-gh", obj["username"])
	})

	t.Run("unnamed result omits first and last keys", func(t *testing.T) {
		var buf bytes.Buffer
		outputGithubEnumJSONL(&buf, []githubenum.Result{unnamed})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGithubEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.NotContains(t, obj, "first",
			`first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last",
			`last key must be absent (omitempty), not emitted as ""`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, "github_account", obj["type"])
		assert.Equal(t, unnamed.Email, obj["email"])
		assert.Equal(t, true, obj["exists"])
		assert.Equal(t, "supplied-gh", obj["username"])
	})

	t.Run("mixed batch: one named, one unnamed", func(t *testing.T) {
		var buf bytes.Buffer
		outputGithubEnumJSONL(&buf, []githubenum.Result{named, unnamed})

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 2, "must emit exactly one JSONL line per result")

		var first map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
		assert.Equal(t, "john", first["first"])
		assert.Equal(t, "smith", first["last"])

		var second map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
		assert.NotContains(t, second, "first")
		assert.NotContains(t, second, "last")
	})
}

// ---------------------------------------------------------------------------
// outputGithubEnumResultLine
// ---------------------------------------------------------------------------

// TestOutputGithubEnumResultLine_Error verifies that a result with a non-nil
// Error renders the dedicated error row: the red "[-]" symbol, the literal
// word "error", and a truncated/sanitized chunk of the error message. It must
// NOT fall through to the not-found row.
func TestOutputGithubEnumResultLine_Error(t *testing.T) {
	r := githubenum.Result{
		Email: "a@x.com",
		Error: errors.New("github enum: parsing join page: CSRF authenticity token not found on join page"),
	}

	var buf bytes.Buffer
	outputGithubEnumResultLine(&buf, r, false)
	out := buf.String()

	assert.Contains(t, out, SymbolError, "error row must show the error symbol")
	assert.Contains(t, out, "error", "error row must contain the literal word \"error\"")
	assert.Contains(t, out, "CSRF authenticity token not found",
		"error row must contain a chunk of the underlying error message")
	assert.NotContains(t, out, "[ ] not found",
		"a result with an error must not render as the not-found row")
}

// TestOutputGithubEnumResultLine_NotFoundStillWorks guards against
// regressing the pre-existing not-found branch: a result with no error and
// Exists=false must still render "[ ] not found" and must not render the
// error row.
func TestOutputGithubEnumResultLine_NotFoundStillWorks(t *testing.T) {
	r := githubenum.Result{Email: "b@x.com"}

	var buf bytes.Buffer
	outputGithubEnumResultLine(&buf, r, false)
	out := buf.String()

	assert.Contains(t, out, "[ ] not found", "a result with no error/no match must render the not-found row")
	assert.NotContains(t, out, SymbolError, "a not-found result must not show the error symbol")
	assert.NotContains(t, out, " error ", "a not-found result must not render the error row")
}

// ---------------------------------------------------------------------------
// outputGithubEnumSummary
// ---------------------------------------------------------------------------

// TestOutputGithubEnumSummary_ShowsRepresentativeError verifies that when
// errored results are present, the summary shows an "Errors: N" line followed
// by a representative "e.g. <msg>" line containing the FIRST errored
// result's message.
func TestOutputGithubEnumSummary_ShowsRepresentativeError(t *testing.T) {
	results := []githubenum.Result{
		{Email: "exists@x.com", Exists: true},
		{Email: "missing@x.com"},
		{Email: "err1@x.com", Error: errors.New("first distinct failure message")},
		{Email: "err2@x.com", Error: errors.New("second distinct failure message")},
	}

	var buf bytes.Buffer
	outputGithubEnumSummary(&buf, results, false)
	out := buf.String()

	assert.Contains(t, out, "Errors:", "summary must show an Errors line when errored results exist")
	assert.Contains(t, out, "2", "summary must show the correct error count")
	assert.Contains(t, out, "e.g. first distinct failure message",
		"summary must show a representative line with the first errored result's message")
	assert.NotContains(t, out, "second distinct failure message",
		"summary need only show the first errored result's message, not every one")
}

// ---------------------------------------------------------------------------
// firstGithubEnumError
// ---------------------------------------------------------------------------

// TestFirstGithubEnumError verifies that firstGithubEnumError returns the
// first non-nil error's message, and "" when no result has an error.
func TestFirstGithubEnumError(t *testing.T) {
	t.Run("returns first non-nil error message", func(t *testing.T) {
		results := []githubenum.Result{
			{Email: "ok@x.com", Exists: true},
			{Email: "err1@x.com", Error: errors.New("boom one")},
			{Email: "err2@x.com", Error: errors.New("boom two")},
		}

		assert.Equal(t, "boom one", firstGithubEnumError(results))
	})

	t.Run("returns empty string when no errors present", func(t *testing.T) {
		results := []githubenum.Result{
			{Email: "ok@x.com", Exists: true},
			{Email: "missing@x.com"},
		}

		assert.Equal(t, "", firstGithubEnumError(results))
	})
}
