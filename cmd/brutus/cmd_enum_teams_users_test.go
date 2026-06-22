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

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// Test 17: users subcommand is registered on enumTeamsCmd
// ---------------------------------------------------------------------------

func TestTeamsUsersSubcommandRegistered(t *testing.T) {
	var usersFound bool
	for _, cmd := range enumTeamsCmd.Commands() {
		if cmd.Use == "users" {
			usersFound = true
			break
		}
	}
	require.True(t, usersFound, "users subcommand must be registered with enumTeamsCmd")
}

// ---------------------------------------------------------------------------
// Test 18: Flag presence on enumTeamsUsersCmd, no shorthand collisions
// ---------------------------------------------------------------------------

func TestEnumTeamsUsersCmd_Flags(t *testing.T) {
	flags := enumTeamsUsersCmd.Flags()

	t.Run("emails flag -e exists", func(t *testing.T) {
		f := flags.Lookup("emails")
		require.NotNil(t, f, "--emails flag must exist on users subcommand")
		short := flags.ShorthandLookup("e")
		require.NotNil(t, short, "-e shorthand must exist on users subcommand")
	})

	t.Run("email-file flag -E exists", func(t *testing.T) {
		f := flags.Lookup("email-file")
		require.NotNil(t, f, "--email-file flag must exist on users subcommand")
		short := flags.ShorthandLookup("E")
		require.NotNil(t, short, "-E shorthand must exist on users subcommand")
	})

	t.Run("access-token flag exists", func(t *testing.T) {
		f := flags.Lookup("access-token")
		require.NotNil(t, f, "--access-token flag must exist on users subcommand")
	})

	t.Run("refresh-token flag exists", func(t *testing.T) {
		f := flags.Lookup("refresh-token")
		require.NotNil(t, f, "--refresh-token flag must exist on users subcommand")
	})

	t.Run("token-file flag exists", func(t *testing.T) {
		f := flags.Lookup("token-file")
		require.NotNil(t, f, "--token-file flag must exist on users subcommand")
	})

	t.Run("presence flag exists", func(t *testing.T) {
		f := flags.Lookup("presence")
		require.NotNil(t, f, "--presence flag must exist on users subcommand")
	})

	t.Run("no local -t shorthand on users subcommand", func(t *testing.T) {
		// -t must not be defined locally — it collides with the global --threads/-t.
		localT := flags.ShorthandLookup("t")
		require.Nil(t, localT,
			"users subcommand must not define a local -t shorthand (collides with global --threads/-t)")
	})

	t.Run("no local -s shorthand on users subcommand", func(t *testing.T) {
		// -s is reserved for consistency with the auth path (which has --scope/-s).
		localS := flags.ShorthandLookup("s")
		require.Nil(t, localS,
			"users subcommand must not define a local -s shorthand (reserved for auth path consistency)")
	})
}

// ---------------------------------------------------------------------------
// Test 19: outputTeamsEnumJSONL — type, tri-state, no token fields, control char escape
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumJSONL(t *testing.T) {
	maliciousName := "EVIL\x1b[31mRED"
	results := []teams.EnumResult{
		{
			Email:        "alice@example.com",
			Exists:       teams.ExistenceYes,
			DisplayName:  "Alice Smith",
			MRI:          "8:orgid:alice",
			Availability: "Available",
			DeviceType:   "Desktop",
		},
		{
			Email:  "nobody@example.com",
			Exists: teams.ExistenceNo,
		},
		{
			Email:  "error@example.com",
			Exists: teams.ExistenceUnknown,
			Error:  errors.New("connection refused"),
		},
		{
			Email:       "evil@example.com",
			Exists:      teams.ExistenceYes,
			DisplayName: maliciousName,
		},
	}

	var buf bytes.Buffer
	outputTeamsEnumJSONL(&buf, results)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 4, "must emit exactly one JSON line per result")

	// Line 0: ExistenceYes with presence.
	var obj0 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj0), "line 0 must be valid JSON")
	assert.Equal(t, "teams_enum", obj0["type"])
	assert.Equal(t, "alice@example.com", obj0["email"])
	assert.Equal(t, string(teams.ExistenceYes), obj0["exists"])
	assert.Equal(t, "Alice Smith", obj0["display_name"])
	assert.Equal(t, "8:orgid:alice", obj0["mri"])
	assert.Equal(t, "Available", obj0["availability"])
	assert.Equal(t, "Desktop", obj0["device_type"])
	_, hasError := obj0["error"]
	assert.False(t, hasError, "no error field for success result")

	// Line 1: ExistenceNo.
	var obj1 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &obj1))
	assert.Equal(t, string(teams.ExistenceNo), obj1["exists"])

	// Line 2: ExistenceUnknown with error.
	var obj2 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &obj2))
	assert.Equal(t, string(teams.ExistenceUnknown), obj2["exists"])
	assert.NotEmpty(t, obj2["error"], "error field must be present for error result")

	// NO token fields in any line.
	tokenFields := []string{"access_token", "refresh_token", "id_token", "token"}
	for i, line := range lines {
		for _, field := range tokenFields {
			assert.NotContains(t, line, field,
				"line %d must not contain token field %q", i, field)
		}
	}

	// Line 3: malicious DisplayName — encoding/json must escape the ESC byte.
	var obj3 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[3]), &obj3))
	// After JSON encoding, 0x1B must appear as  (not raw 0x1B).
	assert.NotContains(t, lines[3], "\x1b",
		"raw ESC byte must be escaped by encoding/json in JSONL output")
}

// ---------------------------------------------------------------------------
// Test 20: outputTeamsEnumHuman — ANSI sanitization strips ESC byte
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumHuman_Sanitization(t *testing.T) {
	evilName := "\x1b[31mEVIL"
	results := []teams.EnumResult{
		{
			Email:       "evil@example.com",
			Exists:      teams.ExistenceYes,
			DisplayName: evilName,
		},
	}

	var buf bytes.Buffer
	// Reset global state touched by flagQuiet / flagVerbose.
	origQuiet := flagQuiet
	origVerbose := flagVerbose
	flagQuiet = false
	flagVerbose = false
	defer func() {
		flagQuiet = origQuiet
		flagVerbose = origVerbose
	}()

	outputTeamsEnumHuman(&buf, results, false /* useColor */)
	out := buf.String()

	// The raw ESC byte 0x1B must not appear in the output (sanitizeTerminal strips it).
	assert.NotContains(t, out, "\x1b",
		"raw ESC byte 0x1B must be stripped by sanitizeTerminal in human output")
	// [31m (the ANSI color sequence payload) must also be absent.
	assert.NotContains(t, out, "[31m",
		"ANSI CSI sequence payload must be stripped from human output")
}
