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

	t.Run("no-presence flag exists", func(t *testing.T) {
		f := flags.Lookup("no-presence")
		require.NotNil(t, f, "--no-presence flag must exist on users subcommand")
		assert.Equal(t, "false", f.DefValue,
			"--no-presence must default to false (presence is on by default)")
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

	t.Run("include-consumer flag exists with default false and no shorthand", func(t *testing.T) {
		f := flags.Lookup("include-consumer")
		require.NotNil(t, f, "--include-consumer flag must exist on users subcommand")
		assert.Equal(t, "false", f.DefValue,
			"--include-consumer must default to false (corporate-only is the safe default)")
		// No shorthand must be registered (none was registered in init()).
		for _, short := range []string{"i", "c"} {
			assert.Nil(t, flags.ShorthandLookup(short),
				"users subcommand must not register -%s shorthand for --include-consumer", short)
		}
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
// Test 21: --domain, --format, --limit flags exist on enumTeamsUsersCmd
// ---------------------------------------------------------------------------

// TestEnumTeamsUsersCmd_GenerationFlags verifies that the three generation
// flags added to enumTeamsUsersCmd are correctly registered with the right
// shorthands, default values, and no collision with -t/-s.
func TestEnumTeamsUsersCmd_GenerationFlags(t *testing.T) {
	flags := enumTeamsUsersCmd.Flags()

	t.Run("--domain flag exists with -d shorthand", func(t *testing.T) {
		f := flags.Lookup("domain")
		require.NotNil(t, f, "--domain flag must exist on users subcommand")
		short := flags.ShorthandLookup("d")
		require.NotNil(t, short, "-d shorthand must exist for --domain")
		assert.Equal(t, "", f.DefValue, "--domain default must be empty string")
	})

	t.Run("--format flag exists with default first.last", func(t *testing.T) {
		f := flags.Lookup("format")
		require.NotNil(t, f, "--format flag must exist on users subcommand")
		assert.Equal(t, "first.last", f.DefValue,
			"--format must default to first.last")
	})

	t.Run("--limit flag exists with default 0", func(t *testing.T) {
		f := flags.Lookup("limit")
		require.NotNil(t, f, "--limit flag must exist on users subcommand")
		assert.Equal(t, "0", f.DefValue,
			"--limit must default to 0 (unlimited)")
	})

	t.Run("no -t shorthand collision", func(t *testing.T) {
		// -t is reserved for the global --threads persistent flag.
		localT := flags.ShorthandLookup("t")
		require.Nil(t, localT,
			"users subcommand must not define a local -t shorthand (collides with global --threads/-t)")
	})

	t.Run("no -s shorthand collision", func(t *testing.T) {
		// -s is reserved for consistency with the auth path.
		localS := flags.ShorthandLookup("s")
		require.Nil(t, localS,
			"users subcommand must not define a local -s shorthand (reserved for auth path consistency)")
	})
}

// ---------------------------------------------------------------------------
// Tests 22-26: teamsEnumTargetList / teamsEnumGenerate (10T-535, 7/8)
//
// teamsEnumTargets() ([]string, error) is retargeted onto
// teamsEnumTargetList() ([]enum.Target, error) — the Target-returning
// function that carries each generated address's name (mirrors
// googleEnumTargetList / githubEnumTargetList / gravatarEnumTargetList /
// microsoft365EnumTargetList). teamsEnumGenerate() is retargeted from
// ([]string, error) to ([]enum.Target, error) for the same reason. Every
// prior assertion (trim, dedup, "provide --domain" error, --limit capping,
// invalid-format error, limit-zero-returns-all, frequency-ranked ordering)
// is preserved below; there is no dead adapter left behind pinning the old
// []string signatures.
// ---------------------------------------------------------------------------

// resetTeamsEnumTargetFlags saves and restores every package-level flag var
// touched by the teamsEnumTargetList/teamsEnumGenerate tests below, so tests
// in this file (and cmd_enum_teams_names_test.go, which shares this helper)
// never leak flag state into each other or into other test files.
func resetTeamsEnumTargetFlags() (restore func()) {
	origEmails := flagTeamsEnumEmails
	origEmailFile := flagTeamsEnumEmailFile
	origDomain := flagTeamsEnumDomain
	origFormat := flagTeamsEnumFormat
	origLimit := flagTeamsEnumLimit
	origQuiet := flagQuiet
	origJSON := flagJSON
	return func() {
		flagTeamsEnumEmails = origEmails
		flagTeamsEnumEmailFile = origEmailFile
		flagTeamsEnumDomain = origDomain
		flagTeamsEnumFormat = origFormat
		flagTeamsEnumLimit = origLimit
		flagQuiet = origQuiet
		flagJSON = origJSON
	}
}

// TestTeamsEnumGenerate_Basic verifies that teamsEnumGenerate produces the
// expected number of Targets whose Email ends with the target domain, that
// every generated Target carries a non-empty First/Last, and that the
// statistically most-likely first name / last name pair leads the list —
// retargeted from the []string-returning teamsEnumGenerate onto the
// []enum.Target-returning one.
func TestTeamsEnumGenerate_Basic(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumDomain = "example.com"
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 5
	// Suppress the stderr note so test output stays clean.
	flagQuiet = true
	flagJSON = false

	targets, err := teamsEnumGenerate()
	require.NoError(t, err, "teamsEnumGenerate must not return an error for a valid format")
	require.Len(t, targets, 5, "teamsEnumGenerate must return exactly --limit targets")

	for i, target := range targets {
		assert.True(t, strings.HasSuffix(target.Email, "@example.com"),
			"every generated target's Email must end with @example.com, got: %q", target.Email)
		assert.NotEmpty(t, target.First, "target %d (%q): a generated target must carry a non-empty First", i, target.Email)
		assert.NotEmpty(t, target.Last, "target %d (%q): a generated target must carry a non-empty Last", i, target.Email)
	}

	// The frequency-ranked list places john.smith first, so the leading entry
	// must be john.smith@example.com.
	assert.Equal(t, "john.smith@example.com", targets[0].Email,
		"first generated target's Email must be john.smith@example.com (highest-ranked pair)")
}

// TestTeamsEnumGenerate_InvalidFormat verifies that teamsEnumGenerate returns
// a non-nil error containing valid format names when an unknown format is
// provided, and returns nil targets, exercising the ListFormats validation
// gate added to protect against GenerateEmails silently returning an empty
// list — retargeted onto the []enum.Target signature.
func TestTeamsEnumGenerate_InvalidFormat(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumDomain = "example.com"
	flagTeamsEnumFormat = "bogus"
	flagTeamsEnumLimit = 0
	flagQuiet = true
	flagJSON = false

	targets, err := teamsEnumGenerate()
	require.Error(t, err, "teamsEnumGenerate must return an error for an invalid format")
	assert.Nil(t, targets, "no targets must be returned on error")
	// The error message must mention at least one valid format to be actionable.
	assert.Contains(t, err.Error(), "first.last",
		"error message must list valid formats so the user knows what to fix")
}

// TestTeamsEnumTargetList_DomainCombinesWithEmails verifies that when both
// --emails and --domain are provided, teamsEnumTargetList returns the -e
// address alongside the generated @example.com targets, with no duplicates,
// and that the explicit -e target carries no name while the generated ones
// do — retargeted from TestTeamsEnumTargets_DomainCombinesWithEmails onto the
// []enum.Target signature.
func TestTeamsEnumTargetList_DomainCombinesWithEmails(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = "alice@x.com"
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = "example.com"
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 3
	flagQuiet = true
	flagJSON = false

	result, err := teamsEnumTargetList()
	require.NoError(t, err, "teamsEnumTargetList must not error when both -e and --domain are set")

	emails := enumTargetEmails(result)

	// Must contain the explicit -e address.
	assert.Contains(t, emails, "alice@x.com",
		"result must contain the explicit -e email address")

	// Count generated @example.com emails.
	var exampleCount int
	for _, e := range emails {
		if strings.HasSuffix(e, "@example.com") {
			exampleCount++
		}
	}
	assert.Equal(t, 3, exampleCount,
		"result must contain exactly --limit (3) generated @example.com targets")

	// Total must be at least 4 (1 explicit + 3 generated).
	assert.GreaterOrEqual(t, len(result), 4,
		"result must have at least 4 targets (1 explicit + 3 generated)")

	// Verify deduplication: no address appears twice.
	seen := make(map[string]int)
	for _, e := range emails {
		seen[e]++
	}
	for addr, count := range seen {
		assert.Equal(t, 1, count,
			"address %q appears %d times; dedup must ensure each address appears exactly once", addr, count)
	}

	// The explicit -e target carries no name (a supplied address says nothing
	// about whose it is); every --domain-generated target does.
	for _, target := range result {
		if target.Email == "alice@x.com" {
			assert.Empty(t, target.First, "the explicit -e target must have empty First")
			assert.Empty(t, target.Last, "the explicit -e target must have empty Last")
		} else {
			assert.NotEmpty(t, target.First, "target %q: --domain-generated target must carry a non-empty First", target.Email)
			assert.NotEmpty(t, target.Last, "target %q: --domain-generated target must carry a non-empty Last", target.Email)
		}
	}
}

// TestTeamsEnumTargetList_NoSourcesErrors verifies that teamsEnumTargetList
// returns an error when all of --emails, --email-file, and --domain are
// empty. The error message must mention --domain so the user knows
// generation is an option — retargeted from
// TestTeamsEnumTargets_NoSourcesErrors onto the []enum.Target signature.
func TestTeamsEnumTargetList_NoSourcesErrors(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = ""
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = ""

	result, err := teamsEnumTargetList()
	require.Error(t, err, "teamsEnumTargetList must return an error when no email sources are set")
	assert.Nil(t, result, "no results must be returned when there is an error")
	assert.Contains(t, err.Error(), "--domain",
		"error message must mention --domain as a valid source of targets")
}

// TestTeamsEnumGenerate_LimitZeroReturnsAll verifies that limit=0 causes
// teamsEnumGenerate to return the entire embedded wordlist (~248k entries) as
// Targets. It does not pin the exact count to avoid brittleness if the
// wordlist is updated; it checks the list is large (>1000) and bounded
// (<250k+margin) — retargeted onto the []enum.Target signature.
func TestTeamsEnumGenerate_LimitZeroReturnsAll(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumDomain = "example.com"
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 0
	flagQuiet = true
	flagJSON = false

	targets, err := teamsEnumGenerate()
	require.NoError(t, err, "teamsEnumGenerate with limit=0 must not error")
	assert.Greater(t, len(targets), 1000,
		"limit=0 must return a large list (>1000 entries)")
	assert.Less(t, len(targets), 300_000,
		"limit=0 list must be bounded (<300,000 entries; embedded wordlist sanity check)")
}

// ---------------------------------------------------------------------------
// Test 20: outputTeamsEnumResultLine — ANSI sanitization strips ESC byte
// ---------------------------------------------------------------------------

func TestOutputTeamsEnumResultLine_Sanitization(t *testing.T) {
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

	outputTeamsEnumResultLine(&buf, &results[0], false /* useColor */)
	out := buf.String()

	// The raw ESC byte 0x1B must not appear in the output (sanitizeTerminal strips it).
	assert.NotContains(t, out, "\x1b",
		"raw ESC byte 0x1B must be stripped by sanitizeTerminal in human output")
	// [31m (the ANSI color sequence payload) must also be absent.
	assert.NotContains(t, out, "[31m",
		"ANSI CSI sequence payload must be stripped from human output")
}
