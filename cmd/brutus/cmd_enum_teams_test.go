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
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// Command registration
// ---------------------------------------------------------------------------

func TestTeamsCommandRegistered(t *testing.T) {
	// Verify enumActiveCmd is a direct child of enumCmd (hard move).
	var activeFound bool
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "active" {
			activeFound = true
			break
		}
	}
	require.True(t, activeFound, "active subcommand must be registered with enumCmd")

	// Verify enumTeamsCmd is registered with enumActiveCmd (not enumCmd directly).
	var teamsFound bool
	for _, cmd := range enumActiveCmd.Commands() {
		if cmd.Use == "teams" {
			teamsFound = true
			break
		}
	}
	require.True(t, teamsFound, "teams subcommand must be registered with enumActiveCmd (hard move)")

	// Verify enumTeamsAuthCmd is registered with enumTeamsCmd.
	var authFound bool
	for _, cmd := range enumTeamsCmd.Commands() {
		if cmd.Use == "auth" {
			authFound = true
			break
		}
	}
	require.True(t, authFound, "auth subcommand must be registered with enumTeamsCmd")

	// Verify --tenant flag (long-form only).
	tenantFlag := enumTeamsAuthCmd.Flags().Lookup("tenant")
	require.NotNil(t, tenantFlag, "--tenant flag must exist on auth subcommand")
	tenantShort := enumTeamsAuthCmd.Flags().ShorthandLookup("t")
	require.Nil(t, tenantShort, "auth subcommand must not define a local -t shorthand (collides with global --threads/-t)")

	// Verify --client-id flag.
	clientIDFlag := enumTeamsAuthCmd.Flags().Lookup("client-id")
	require.NotNil(t, clientIDFlag, "--client-id flag must exist on auth subcommand")

	// Verify --scope / -s flag.
	scopeFlag := enumTeamsAuthCmd.Flags().Lookup("scope")
	require.NotNil(t, scopeFlag, "--scope flag must exist on auth subcommand")
	scopeShort := enumTeamsAuthCmd.Flags().ShorthandLookup("s")
	require.NotNil(t, scopeShort, "-s shorthand must exist on auth subcommand")
}

// ---------------------------------------------------------------------------
// Flag-default guards (CLI layer regressions for fixes #2 and #3)
// ---------------------------------------------------------------------------

// TestEnumTeamsAuthFlagDefaults guards two CLI-layer regressions:
//
//   - Fix #2: default tenant must be "organizations" (not "common"). A regression
//     back to "common" reintroduces AADSTS70002 failures because the Teams client
//     is not enabled for consumer accounts. This complements the library-layer
//     TestNewClient_Defaults by checking the value that users actually observe
//     through the flag.
//
//   - Fix #3: --no-browser flag must exist and default to false. The flag gates
//     auto-opening the verification URL; its absence would silently break headless
//     workflows.
func TestEnumTeamsAuthFlagDefaults(t *testing.T) {
	t.Run("tenant default is organizations not common", func(t *testing.T) {
		f := enumTeamsAuthCmd.Flags().Lookup("tenant")
		require.NotNil(t, f, "--tenant flag must exist on auth subcommand")
		assert.Equal(t, "organizations", f.DefValue,
			"--tenant default must be \"organizations\"; regression to \"common\" reintroduces AADSTS70002")
	})

	t.Run("no-browser flag exists and defaults to false", func(t *testing.T) {
		f := enumTeamsAuthCmd.Flags().Lookup("no-browser")
		require.NotNil(t, f, "--no-browser flag must exist on auth subcommand")
		assert.Equal(t, "false", f.DefValue,
			"--no-browser must default to false (browser auto-opens unless explicitly disabled)")
	})
}

// ---------------------------------------------------------------------------
// Panic-regression test (fix #1: --tenant shorthand -t collision with global --threads/-t)
// ---------------------------------------------------------------------------

// TestEnumTeamsAuth_NoFlagCollisionPanic is a keystone regression test for the
// cobra panic that fired in mergePersistentFlags when the global persistent
// --threads/-t flag collided with a local -t shorthand on the auth subcommand.
//
// The test:
//  1. Asserts the precondition: rootCmd still registers --threads with shorthand
//     "t", so the collision scenario remains meaningful.
//  2. Executes "enum teams auth --help" through the real rootCmd command tree.
//     --help short-circuits cobra before reaching PersistentPreRunE or the
//     device-code network flow, but it does trigger the flag-merging path that
//     previously panicked.
//  3. Asserts Execute() returns no error and does not panic.
//
// If the -t shorthand is ever re-added to enumTeamsAuthCmd, cobra will panic
// (failing this test) before any assertion runs, making the regression immediately
// visible.
func TestEnumTeamsAuth_NoFlagCollisionPanic(t *testing.T) {
	// Precondition: global --threads flag must still carry the -t shorthand so
	// the collision scenario this test guards is still live. If --threads ever
	// loses its -t shorthand the original bug disappears and this test would
	// become vacuous — asserting the precondition documents that intent.
	threadsFlag := rootCmd.PersistentFlags().ShorthandLookup("t")
	require.NotNil(t, threadsFlag, "global persistent -t shorthand must still exist (expected on --threads)")
	require.Equal(t, "threads", threadsFlag.Name, "global -t shorthand must map to --threads flag")

	// Redirect cobra output so --help text doesn't pollute test output.
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"enum", "active", "teams", "auth", "--help"})

	// Restore global rootCmd state after the test so subsequent tests in the
	// package are not affected by the mutated args/output writers.
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	// Execute must not panic and must return no error. A plain Execute() call
	// panics the test goroutine immediately if the flag-collision bug regresses,
	// which already fails the test. We additionally wrap in a deferred recover
	// to emit a clear diagnostic message rather than an opaque goroutine dump.
	var panicVal interface{}
	func() {
		defer func() { panicVal = recover() }()
		err := rootCmd.Execute()
		assert.NoError(t, err, "rootCmd.Execute() must not return an error for --help")
	}()
	require.Nil(t, panicVal, "rootCmd.Execute() panicked: %v (flag -t shorthand collision?)", panicVal)
}

// ---------------------------------------------------------------------------
// classifyTeamsError
// ---------------------------------------------------------------------------

func TestClassifyTeamsError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		contain string
	}{
		{"ErrExpiredToken", teams.ErrExpiredToken, "expired"},
		{"ErrAccessDenied", teams.ErrAccessDenied, "access denied"},
		{"generic error", fmt.Errorf("connection refused"), "teams auth failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyTeamsError(tc.err)
			require.Error(t, result)
			assert.Contains(t, result.Error(), tc.contain)
		})
	}
}

// ---------------------------------------------------------------------------
// outputTeamsTokenJSONL
// ---------------------------------------------------------------------------

func TestOutputTeamsTokenJSONL(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tok := &teams.TokenSet{
		AccessToken:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.access",
		RefreshToken: "0.AXkArefreshtoken",
		IDToken:      "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.id",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        teams.DefaultScope,
		ExpiresAt:    now.Add(time.Hour),
	}

	var buf bytes.Buffer
	outputTeamsTokenJSONL(&buf, tok)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1, "expected exactly 1 JSONL line")

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

	// Verify type field.
	assert.Equal(t, "teams_token", obj["type"])

	// Verify all token fields are present with correct values.
	// JSON output is the one place full token values should be present.
	assert.Equal(t, tok.AccessToken, obj["access_token"], "access_token must be present in full")
	assert.Equal(t, tok.RefreshToken, obj["refresh_token"], "refresh_token must be present in full")
	assert.Equal(t, tok.IDToken, obj["id_token"], "id_token must be present in full")
	assert.Equal(t, "Bearer", obj["token_type"])
	assert.Equal(t, float64(3600), obj["expires_in"])
	assert.Equal(t, teams.DefaultScope, obj["scope"])

	// expires_at must be present.
	_, hasExpiresAt := obj["expires_at"]
	assert.True(t, hasExpiresAt, "expires_at must be present in JSONL output")
}

// ---------------------------------------------------------------------------
// outputTeamsTokenHuman
// ---------------------------------------------------------------------------

func TestOutputTeamsTokenHuman(t *testing.T) {
	t.Run("access token shows first 20 chars plus ellipsis", func(t *testing.T) {
		tok := &teams.TokenSet{
			AccessToken:  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.signature",
			RefreshToken: "refreshvalue",
			IDToken:      "idvalue",
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
		}
		var buf bytes.Buffer
		outputTeamsTokenHuman(&buf, tok, false)
		out := buf.String()

		// Access token: first 20 runes of the value followed by "..."
		assert.Contains(t, out, "eyJ0eXAiOiJKV1QiLCJh...")
		// Refresh and ID tokens must show <present>, not the actual value.
		assert.Contains(t, out, "<present>")
		assert.NotContains(t, out, "refreshvalue")
		assert.NotContains(t, out, "idvalue")
	})

	t.Run("empty refresh and id token show absent", func(t *testing.T) {
		tok := &teams.TokenSet{
			AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.signature",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		var buf bytes.Buffer
		outputTeamsTokenHuman(&buf, tok, false)
		out := buf.String()

		// Empty refresh and ID tokens must show <absent>.
		assert.Contains(t, out, "<absent>")
	})

	t.Run("short access token is never revealed in full", func(t *testing.T) {
		tok := &teams.TokenSet{
			AccessToken: "shorttoken",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		var buf bytes.Buffer
		outputTeamsTokenHuman(&buf, tok, false)
		out := buf.String()

		// Short tokens must never be printed in full; they show as <present>.
		assert.NotContains(t, out, "shorttoken")
		assert.Contains(t, out, "<present>")
	})

	t.Run("control chars in access token preview are stripped by sanitizeTerminal", func(t *testing.T) {
		tok := &teams.TokenSet{
			AccessToken: "abc\x1b[2Jdefghijklmnopqrstuv",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		var buf bytes.Buffer
		outputTeamsTokenHuman(&buf, tok, false)
		out := buf.String()

		assert.NotContains(t, out, "\x1b")
		assert.NotContains(t, out, "[2J")
	})
}

// ---------------------------------------------------------------------------
// outputTeamsDeviceCodeHuman
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test: teamsEnumDomain
// ---------------------------------------------------------------------------

func TestTeamsEnumDomain(t *testing.T) {
	tests := []struct {
		name   string
		emails []string
		want   string
	}{
		{
			name:   "single domain returns that domain",
			emails: []string{"a@x.com", "b@x.com"},
			want:   "x.com",
		},
		{
			name:   "mixed domains returns (multiple)",
			emails: []string{"a@x.com", "b@y.com"},
			want:   "(multiple)",
		},
		{
			name:   "no @ in any email returns empty string",
			emails: []string{"noemail", "alsononeat"},
			want:   "",
		},
		{
			name:   "empty list returns empty string",
			emails: []string{},
			want:   "",
		},
		{
			name:   "@ at end of string (no domain part) is skipped",
			emails: []string{"trailing@"},
			want:   "",
		},
		{
			name:   "single email with domain",
			emails: []string{"alice@contoso.com"},
			want:   "contoso.com",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := teamsEnumDomain(tc.emails)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: outputTeamsPostureJSONL — type discriminator, field values
// ---------------------------------------------------------------------------

func TestOutputTeamsPostureJSONL(t *testing.T) {
	posture := teams.TenantPosture{
		Domain:              "contoso.com",
		Total:               10,
		UsersFound:          6,
		Blocked403:          2,
		ExternalChatAllowed: "open",
		FederatedObserved:   true,
		PresenceVisible:     true,
		OOOExposed:          3,
		CoExistenceMode:     "TeamsOnly",
	}

	var buf bytes.Buffer
	outputTeamsPostureJSONL(&buf, &posture)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1, "outputTeamsPostureJSONL must emit exactly 1 JSONL line")

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj), "posture line must be valid JSON")

	// Type discriminator must be teams_posture.
	assert.Equal(t, "teams_posture", obj["type"],
		"type field must be \"teams_posture\"")

	// All posture fields must round-trip.
	assert.Equal(t, "contoso.com", obj["domain"])
	assert.Equal(t, float64(10), obj["total"])
	assert.Equal(t, float64(6), obj["users_found"])
	assert.Equal(t, float64(2), obj["blocked_403"])
	assert.Equal(t, "open", obj["external_chat_allowed"])
	assert.Equal(t, true, obj["federated_observed"])
	assert.Equal(t, true, obj["presence_visible"])
	assert.Equal(t, float64(3), obj["ooo_exposed"])
	assert.Equal(t, "TeamsOnly", obj["coexistence_mode"])
}

// ---------------------------------------------------------------------------
// Test: outputTeamsEnumJSONL — config fields (user_type not "type", no tokens,
// ANSI escape sanitization)
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumJSONL_ConfigFields(t *testing.T) {
	acctEnabled := true
	results := []teams.EnumResult{
		{
			Email:             "paul.davis@kindermorgan.com",
			Exists:            teams.ExistenceYes,
			DisplayName:       "Paul Davis",
			MRI:               "8:orgid:abc",
			Type:              "Federated",
			TenantID:          "t-123",
			UserPrincipalName: "paul.davis@kindermorgan.com",
			ObjectID:          "o-456",
			AccountEnabled:    &acctEnabled,
			CoExistenceMode:   "TeamsOnly",
			SourceNetwork:     "Federated",
			OutOfOfficeNote:   "Back Monday",
		},
	}

	var buf bytes.Buffer
	outputTeamsEnumJSONL(&buf, results)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 1)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

	// Object-level type discriminator must be teams_enum.
	assert.Equal(t, "teams_enum", obj["type"],
		"type must be the object discriminator \"teams_enum\", not the user Type value")

	// User type must live in user_type (not in "type").
	assert.Equal(t, "Federated", obj["user_type"],
		"user Type field must be serialized as user_type")

	// Verify all config fields are present.
	assert.Equal(t, "t-123", obj["tenant_id"])
	assert.Equal(t, "paul.davis@kindermorgan.com", obj["user_principal_name"])
	assert.Equal(t, "o-456", obj["object_id"])
	assert.Equal(t, true, obj["account_enabled"])
	assert.Equal(t, "TeamsOnly", obj["coexistence_mode"])
	assert.Equal(t, "Federated", obj["source_network"])
	assert.Equal(t, "Back Monday", obj["out_of_office_note"])

	// No token fields must appear anywhere in the JSONL line (P0-1).
	tokenFields := []string{"access_token", "refresh_token", "id_token"}
	for _, field := range tokenFields {
		assert.NotContains(t, lines[0], field,
			"JSONL output must never contain token field %q", field)
	}
}

// ---------------------------------------------------------------------------
// Test: ANSI escape in OutOfOfficeNote is sanitized in human output and escaped
// in JSONL output
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumJSONL_ANSIEscapeInOOO(t *testing.T) {
	// A malicious OutOfOfficeNote containing a raw ESC byte.
	results := []teams.EnumResult{
		{
			Email:           "evil@contoso.com",
			Exists:          teams.ExistenceYes,
			OutOfOfficeNote: "\x1b[31mRED",
		},
	}

	var buf bytes.Buffer
	outputTeamsEnumJSONL(&buf, results)

	line := strings.TrimSpace(buf.String())

	// encoding/json must have JSON-escaped the 0x1B byte; the raw ESC byte
	// must NOT appear in the output.
	assert.NotContains(t, line, "\x1b",
		"raw ESC byte 0x1B must be JSON-escaped in JSONL output")

	// Verify the JSON is still valid after encoding.
	var escObj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &escObj),
		"JSONL line with JSON-escaped ESC must still be valid JSON")
	assert.NotEmpty(t, escObj["out_of_office_note"],
		"out_of_office_note must be non-empty after JSON encoding")
}

// ---------------------------------------------------------------------------
// Test: sanitizeTerminal strips ESC in CoExistenceMode (posture human output)
// ---------------------------------------------------------------------------

func TestOutputTeamsPostureHuman_SanitizesCoExistenceMode(t *testing.T) {
	// Inject a CoExistenceMode containing an ANSI CSI sequence.
	posture := teams.TenantPosture{
		Domain:              "contoso.com",
		Total:               1,
		UsersFound:          1,
		Blocked403:          0,
		ExternalChatAllowed: "open",
		CoExistenceMode:     "\x1b[2JTeamsOnly",
	}

	var buf bytes.Buffer
	outputTeamsPostureHuman(&buf, &posture, false /* useColor */)
	out := buf.String()

	// Raw ESC must be absent — sanitizeTerminal strips it.
	assert.NotContains(t, out, "\x1b",
		"raw ESC byte must be stripped by sanitizeTerminal in posture human output")
	// The ANSI sequence payload must also be absent.
	assert.NotContains(t, out, "[2J",
		"ANSI CSI sequence payload must be stripped from human posture output")
	// The printable text must survive.
	assert.Contains(t, out, "TeamsOnly",
		"printable CoExistenceMode text must survive sanitizeTerminal")
}

func TestOutputTeamsDeviceCodeHuman(t *testing.T) {
	t.Run("outputs VerificationURI and UserCode", func(t *testing.T) {
		dc := &teams.DeviceCode{
			UserCode:        "ABCD-1234",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       900,
		}
		var buf bytes.Buffer
		outputTeamsDeviceCodeHuman(&buf, dc, false)
		out := buf.String()

		assert.Contains(t, out, "https://microsoft.com/devicelogin")
		assert.Contains(t, out, "ABCD-1234")
	})

	t.Run("ExpiresIn 0 omits expires line", func(t *testing.T) {
		dc := &teams.DeviceCode{
			UserCode:        "WXYZ-5678",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       0,
		}
		var buf bytes.Buffer
		outputTeamsDeviceCodeHuman(&buf, dc, false)
		out := buf.String()

		assert.NotContains(t, out, "Expires in:")
	})

	t.Run("ExpiresIn 900 shows 15m", func(t *testing.T) {
		dc := &teams.DeviceCode{
			UserCode:        "ABCD-1234",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       900,
		}
		var buf bytes.Buffer
		outputTeamsDeviceCodeHuman(&buf, dc, false)
		out := buf.String()

		assert.Contains(t, out, "15m")
	})

	t.Run("control chars in UserCode are stripped by sanitizeTerminal", func(t *testing.T) {
		dc := &teams.DeviceCode{
			UserCode:        "AB\x1b[2JCD-1234",
			VerificationURI: "https://microsoft.com/devicelogin",
		}
		var buf bytes.Buffer
		outputTeamsDeviceCodeHuman(&buf, dc, false)
		out := buf.String()

		// The ESC sequence must be stripped.
		assert.NotContains(t, out, "\x1b")
		assert.NotContains(t, out, "[2J")
		// Printable characters must survive.
		assert.Contains(t, out, "ABCD-1234")
	})
}
