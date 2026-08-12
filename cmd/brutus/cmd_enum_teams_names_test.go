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

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// teamsEnumTargetList — name propagation (10T-535, 7/8)
//
// Mirrors TestMicrosoft365EnumTargetList_InlineEmails /
// TestMicrosoft365EnumTargetList_DomainGeneratedCarriesName: a CLI-supplied
// address carries no name (a supplied address says nothing about whose it
// is); a --domain-generated address carries the non-empty First/Last its
// username was built from.
// ---------------------------------------------------------------------------

// TestTeamsEnumTargetList_InlineEmails verifies that --emails CSV is parsed,
// trimmed, and deduplicated, and that every CLI-supplied target carries no
// name.
func TestTeamsEnumTargetList_InlineEmails(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = "alice@example.com,bob@example.com,alice@example.com"
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = ""

	got, err := teamsEnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	// Deduplication: alice@example.com appears twice but must appear once.
	assert.Len(t, emails, 2, "deduplication must collapse duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestTeamsEnumTargetList_DomainGeneratedCarriesName verifies that
// --domain-generated targets carry the non-empty First/Last the username was
// built from, unlike CLI-supplied addresses, and that --limit caps the count.
func TestTeamsEnumTargetList_DomainGeneratedCarriesName(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = ""
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = "target.com"
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 5

	got, err := teamsEnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 5, "--limit must cap the number of generated targets")

	for i, target := range got {
		assert.Contains(t, target.Email, "@target.com", "target %d must be for the requested domain", i)
		assert.NotEmpty(t, target.First, "target %d (%q): a --domain-generated target must carry a non-empty First", i, target.Email)
		assert.NotEmpty(t, target.Last, "target %d (%q): a --domain-generated target must carry a non-empty Last", i, target.Email)
	}
}

// TestTeamsEnumGenerate_ReusesSharedGenerator verifies that teamsEnumGenerate
// reuses enum.GenerateCandidates (via capResults and Candidate.Target),
// matching the google/gravatar/github/microsoft365 generate pattern — no
// duplicated generation logic.
func TestTeamsEnumGenerate_ReusesSharedGenerator(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumDomain = "target.com"
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 0
	flagQuiet = true
	flagJSON = false

	generated, err := teamsEnumGenerate()
	require.NoError(t, err)

	candidates, err := enum.GenerateCandidates("first.last")
	require.NoError(t, err)

	want := make([]enum.Target, len(candidates))
	for i, c := range candidates {
		want[i] = c.Target("target.com")
	}

	assert.Equal(t, want, generated,
		"teamsEnumGenerate must reuse enum.GenerateCandidates (via capResults and Candidate.Target), matching the google/gravatar/github/microsoft365 generate pattern")
}

// ---------------------------------------------------------------------------
// THE CASING QUESTION (10T-535, 7/8).
//
// teams.EnumerateOne echoes the email it is given verbatim on
// EnumResult.Email (pkg/enum/teams/enum.go: `res := EnumResult{Email:
// email}`, with no strings.ToLower anywhere in that function, in search, or
// in EnumerateWith's per-email loop). This mirrors microsoft365 (which also
// never re-cases the address it is handed) and is the OPPOSITE of gravatar
// (which lower-cases a COPY of the address, only for HashEmail's MD5 digest,
// while still storing the original casing... except gravatarEnumTargetList
// itself lower-cases the stored Target.Email field, per that PR's trap test).
//
// Therefore teamsEnumTargetList must key its dedup "seen" set on the
// lower-cased address (case-insensitive dedup, since Teams search is
// presumably case-insensitive like the other directory lookups) while
// preserving the first-seen ORIGINAL casing on the returned Target.Email —
// never lower-casing the Target field itself. If it lower-cased Target.Email,
// the address stored would no longer match what teams.EnumerateOne echoes
// back on EnumResult.Email for a mixed-case --domain, and
// enumNamesByEmail/enumNameFor's lookup (keyed on the exact address) would
// silently fail to recover the generated name.
// ---------------------------------------------------------------------------

// TestTeamsEnumTargetList_CaseInsensitiveDedup verifies that dedup keys on
// the lowercased email while preserving the first-seen casing on the
// returned Target.Email.
func TestTeamsEnumTargetList_CaseInsensitiveDedup(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = "Alice@Contoso.com,alice@contoso.com,BOB@contoso.com"
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = ""

	got, err := teamsEnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	// Case-variant duplicates collapse: "Alice@Contoso.com" and
	// "alice@contoso.com" are the same target.
	assert.Len(t, emails, 2, "case-variant duplicates must collapse")

	// The first-seen original casing must be preserved, not a lowercased form.
	assert.Contains(t, emails, "Alice@Contoso.com",
		"first-seen casing must be preserved")
	assert.NotContains(t, emails, "alice@contoso.com",
		"the later-seen lowercase duplicate must not also appear")
	assert.Contains(t, emails, "BOB@contoso.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestTeamsEnumTargetList_GeneratedAddressesRetainOriginalCasingForNameLookup
// generates with a MIXED-CASE --domain and asserts:
//  1. Every returned Target's Email retains that exact mixed-case domain (it
//     must NOT be lower-cased away).
//  2. Every generated target's name is recoverable via enumNamesByEmail +
//     enumNameFor, keyed on the address teams.EnumerateOne will actually
//     echo back — target.Email itself, original casing intact.
//  3. A lookup keyed on the independently lower-cased form of that same
//     address must NOT recover a name — proving the index is keyed on the
//     original-cased address the checker echoes, not a normalized one.
func TestTeamsEnumTargetList_GeneratedAddressesRetainOriginalCasingForNameLookup(t *testing.T) {
	defer resetTeamsEnumTargetFlags()()

	flagTeamsEnumEmails = ""
	flagTeamsEnumEmailFile = ""
	flagTeamsEnumDomain = "Contoso.COM" // mixed-case domain: the trap.
	flagTeamsEnumFormat = "first.last"
	flagTeamsEnumLimit = 10

	got, err := teamsEnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 10, "--limit must cap the number of generated targets")

	for i, target := range got {
		// The address stored on the Target must retain the EXACT mixed-case
		// domain the operator supplied via --domain: this is the exact
		// address enumTargetEmails() will hand to teams.Enumerator.EnumerateWith,
		// and teams.EnumerateOne echoes back the address it is given verbatim
		// (EnumResult{Email: email}, no re-casing) on EnumResult.Email.
		require.Contains(t, target.Email, "@Contoso.COM",
			"target %d (%q): Target.Email must retain the mixed-case --domain exactly as supplied — teams.EnumerateOne echoes the address verbatim on EnumResult.Email, so lower-casing Target.Email here would desync the stored address from what the checker actually receives and echoes back", i, target.Email)

		lowered := strings.ToLower(target.Email)
		require.NotEqual(t, lowered, target.Email,
			"target %d (%q): Target.Email must NOT be lower-cased — the mixed-case --domain casing must survive into the Target field itself, not just be discarded by a throwaway local variable", i, target.Email)
	}

	// enumNamesByEmail/enumNameFor are the shared framework helpers
	// (unmodified, reused from cmd_enum.go) that runEnumTeamsUsers wires up
	// exactly like runEnumGoogle/runEnumGithub/runEnumGravatar/runEnumMicrosoft365:
	// names := enumNamesByEmail(targets), then each onResult callback does
	// res.First, res.Last = enumNameFor(names, res.Email). Building the index
	// from the SAME already-original-cased targets slice that
	// teamsEnumTargetList returned is what keeps the lookup key byte-identical
	// to the address the checker echoes back.
	names := enumNamesByEmail(got)
	require.Len(t, names, len(got), "every generated target must be indexed by enumNamesByEmail")

	for i, target := range got {
		// Simulate the checker echoing the address back on a Result:
		// teams.EnumerateOne sets EnumResult{Email: email} verbatim from the
		// email parameter it is given, which is target.Email itself —
		// original casing intact.
		echoedByChecker := target.Email

		first, last := enumNameFor(names, echoedByChecker)
		assert.NotEmpty(t, first,
			"target %d (%q): name lookup keyed on the checker-echoed (original-cased) address must recover a non-empty First — an empty result here means the index was built on a re-cased address and the name silently vanished", i, target.Email)
		assert.NotEmpty(t, last,
			"target %d (%q): name lookup keyed on the checker-echoed (original-cased) address must recover a non-empty Last — an empty result here means the index was built on a re-cased address and the name silently vanished", i, target.Email)
		assert.Equal(t, target.First, first, "target %d: recovered First must match the target's own First", i)
		assert.Equal(t, target.Last, last, "target %d: recovered Last must match the target's own Last", i)

		// A lookup keyed on the independently LOWER-CASED form of the same
		// address must fail to recover the name: this proves the index is
		// keyed on the exact original-cased address, not a normalized one.
		loweredKey := strings.ToLower(echoedByChecker)
		require.NotEqual(t, echoedByChecker, loweredKey,
			"target %d: sanity check — the mixed-case domain must make the lower-cased key differ from the original, or this assertion is vacuous", i)
		firstLowered, lastLowered := enumNameFor(names, loweredKey)
		assert.Empty(t, firstLowered,
			"target %d: a lookup keyed on the lower-cased address must NOT recover a name — the index must be keyed on the original-cased (checker-echoed) address, not a lower-cased one", i)
		assert.Empty(t, lastLowered,
			"target %d: a lookup keyed on the lower-cased address must NOT recover a name — the index must be keyed on the original-cased (checker-echoed) address, not a lower-cased one", i)
	}
}

// ---------------------------------------------------------------------------
// THE WRINKLE UNIQUE TO TEAMS (10T-535, 7/8): a generated name is NOT a
// display name.
//
// teams.EnumResult.DisplayName (pkg/enum/teams/enum.go:63) is TENANT-PROVIDED
// data from the Teams API, already rendered by the human output
// (outputTeamsEnumResultLine, cmd_enum_output.go:544, which truncates +
// sanitizes it). The First/Last this PR populates are BRUTUS-GENERATED
// guesses attached in the onResult callback via enumNameFor — a different
// kind of claim entirely. They emit under distinct JSON keys ("first"/"last"
// vs the existing "display_name"), and neither may fall back to the other in
// either direction: a result may have a DisplayName and no generated name (a
// supplied address), a generated name and no DisplayName (a 403 carries
// none), both, or neither.
// ---------------------------------------------------------------------------

// TestOutputTeamsEnumJSONL_GeneratedNameVsDisplayName pins the
// never-conflate-the-two-names rule across all four combinations, in the
// default (non-blocked) branch of outputTeamsEnumJSONL.
func TestOutputTeamsEnumJSONL_GeneratedNameVsDisplayName(t *testing.T) {
	t.Run("both DisplayName and generated name present: all three keys correct, no substitution", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:       "john.smith@contoso.com",
				Exists:      teams.ExistenceYes,
				DisplayName: "Jonathan A. Smith", // tenant-provided; deliberately differs from the generated guess below
				MRI:         "8:orgid:abc",
				First:       "john",  // brutus-generated guess
				Last:        "smith", // brutus-generated guess
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "john", obj["first"], "first must carry the brutus-generated guess")
		assert.Equal(t, "smith", obj["last"], "last must carry the brutus-generated guess")
		assert.Equal(t, "Jonathan A. Smith", obj["display_name"],
			"display_name must carry the tenant-provided DisplayName untouched — it must NOT be replaced or altered by the generated guess")

		// Pre-existing keys must be unaffected by the new fields.
		assert.Equal(t, "teams_enum", obj["type"])
		assert.Equal(t, "john.smith@contoso.com", obj["email"])
		assert.Equal(t, string(teams.ExistenceYes), obj["exists"])
		assert.Equal(t, "8:orgid:abc", obj["mri"])
		_, hasRestricted := obj["details_restricted"]
		assert.False(t, hasRestricted, "details_restricted must remain absent (omitempty) for ExistenceYes")
	})

	t.Run("DisplayName present, no generated name: first/last omitted, displayName kept", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:       "supplied@contoso.com", // operator-supplied address: no generated name
				Exists:      teams.ExistenceYes,
				DisplayName: "Supplied User",
				MRI:         "8:orgid:def",
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.NotContains(t, obj, "first", `first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last", `last key must be absent (omitempty), not emitted as ""`)
		assert.Equal(t, "Supplied User", obj["display_name"],
			"display_name must still be emitted even though there is no generated name — the absence of one name must not suppress the other")
	})

	t.Run("generated name present, no DisplayName: first/last emitted, displayName omitted", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:  "carol.lee@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "8:orgid:ghi",
				First:  "carol",
				Last:   "lee",
				// DisplayName intentionally left empty (e.g. absent from the API response).
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "carol", obj["first"])
		assert.Equal(t, "lee", obj["last"])
		assert.NotContains(t, obj, "display_name",
			`display_name key must be absent (omitempty) when the tenant returned none — the generated name must never be used to fabricate a display name`)
	})

	t.Run("neither DisplayName nor generated name present: both omitted", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:  "nobody-named@contoso.com",
				Exists: teams.ExistenceYes,
				MRI:    "8:orgid:jkl",
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.NotContains(t, obj, "first")
		assert.NotContains(t, obj, "last")
		assert.NotContains(t, obj, "display_name")
	})
}

// ---------------------------------------------------------------------------
// Both outputTeamsEnumJSONL branches must carry the generated name
// (10T-535, 7/8).
//
// outputTeamsEnumJSONL (cmd_enum_output.go:625) has two branches: the
// ExistenceBlocked (details-restricted) branch, which omits every
// tenant-provided field because a 403 carries none, and the default branch.
// A generated name is a property of the ADDRESS brutus built, not of
// whether the tenant let brutus see details about it — so it must survive
// into the blocked branch exactly like the default branch.
// ---------------------------------------------------------------------------

// TestOutputTeamsEnumJSONL_GeneratedNameInBlockedBranch verifies that the
// generated First/Last survive into the ExistenceBlocked branch, while
// tenant-provided metadata (which a 403 never carries) stays absent, and that
// a nameless (CLI-supplied) blocked result still omits first/last.
func TestOutputTeamsEnumJSONL_GeneratedNameInBlockedBranch(t *testing.T) {
	t.Run("blocked result with a generated name still emits first/last", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:  "dave.park@contoso.com",
				Exists: teams.ExistenceBlocked,
				First:  "dave",
				Last:   "park",
				// DisplayName/MRI intentionally left empty: a 403 carries none.
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, string(teams.ExistenceYes), obj["exists"], "ExistenceBlocked must serialize as exists=yes")
		assert.Equal(t, true, obj["details_restricted"], "ExistenceBlocked must set details_restricted=true")

		assert.Equal(t, "dave", obj["first"], "the generated First must survive into the blocked branch")
		assert.Equal(t, "park", obj["last"], "the generated Last must survive into the blocked branch")

		// The blocked branch must still omit tenant-provided metadata (a 403
		// carries none of this).
		for _, key := range []string{"display_name", "mri", "account_type"} {
			_, ok := obj[key]
			assert.False(t, ok, "key %q must remain absent for ExistenceBlocked (no metadata in a 403)", key)
		}
	})

	t.Run("blocked result with no generated name (supplied address) omits first/last", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:  "supplied-blocked@contoso.com",
				Exists: teams.ExistenceBlocked,
				// No First/Last: this address was supplied via --emails, not generated.
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.NotContains(t, obj, "first")
		assert.NotContains(t, obj, "last")
	})
}

// TestOutputTeamsEnumJSONL_PreExistingKeysUnaffectedByNameFields verifies
// that adding first/last does not alter any pre-existing field's key name or
// value, in either outputTeamsEnumJSONL branch (10T-535, 7/8, required test
// 5: type/email/exists/displayName/MRI/details_restricted unchanged).
func TestOutputTeamsEnumJSONL_PreExistingKeysUnaffectedByNameFields(t *testing.T) {
	t.Run("default branch", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:        "alice@contoso.com",
				Exists:       teams.ExistenceYes,
				DisplayName:  "Alice Smith",
				MRI:          "8:orgid:abc",
				Availability: "Available",
				DeviceType:   "Desktop",
				First:        "alice",
				Last:         "smith",
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "teams_enum", obj["type"])
		assert.Equal(t, "alice@contoso.com", obj["email"])
		assert.Equal(t, string(teams.ExistenceYes), obj["exists"])
		assert.Equal(t, "Alice Smith", obj["display_name"])
		assert.Equal(t, "8:orgid:abc", obj["mri"])
		assert.Equal(t, "corporate", obj["account_type"])
		assert.Equal(t, "Available", obj["availability"])
		assert.Equal(t, "Desktop", obj["device_type"])
		_, hasRestricted := obj["details_restricted"]
		assert.False(t, hasRestricted, "details_restricted must remain absent (omitempty) for ExistenceYes")
	})

	t.Run("blocked branch", func(t *testing.T) {
		results := []teams.EnumResult{
			{
				Email:  "blocked@contoso.com",
				Exists: teams.ExistenceBlocked,
				First:  "block",
				Last:   "eduser",
			},
		}

		var buf bytes.Buffer
		outputTeamsEnumJSONL(&buf, results)

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 1)

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &obj))

		assert.Equal(t, "teams_enum", obj["type"])
		assert.Equal(t, "blocked@contoso.com", obj["email"])
		assert.Equal(t, string(teams.ExistenceYes), obj["exists"], "ExistenceBlocked must still serialize as exists=yes")
		assert.Equal(t, true, obj["details_restricted"])
	})
}
