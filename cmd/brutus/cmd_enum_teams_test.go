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
	// Verify enumTeamsCmd is registered with enumCmd.
	var teamsFound bool
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "teams" {
			teamsFound = true
			break
		}
	}
	require.True(t, teamsFound, "teams subcommand must be registered with enumCmd")

	// Verify enumTeamsAuthCmd is registered with enumTeamsCmd.
	var authFound bool
	for _, cmd := range enumTeamsCmd.Commands() {
		if cmd.Use == "auth" {
			authFound = true
			break
		}
	}
	require.True(t, authFound, "auth subcommand must be registered with enumTeamsCmd")

	// Verify --tenant / -t flag.
	tenantFlag := enumTeamsAuthCmd.Flags().Lookup("tenant")
	require.NotNil(t, tenantFlag, "--tenant flag must exist on auth subcommand")
	tenantShort := enumTeamsAuthCmd.Flags().ShorthandLookup("t")
	require.NotNil(t, tenantShort, "-t shorthand must exist on auth subcommand")

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

	t.Run("short access token always shows ellipsis", func(t *testing.T) {
		tok := &teams.TokenSet{
			AccessToken: "shorttoken",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		var buf bytes.Buffer
		outputTeamsTokenHuman(&buf, tok, false)
		out := buf.String()

		// Even short tokens are marked with "..." to avoid revealing the full value.
		assert.Contains(t, out, "shorttoken...")
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
