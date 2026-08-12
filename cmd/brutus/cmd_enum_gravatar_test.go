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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/gravatar"
)

// ---------------------------------------------------------------------------
// gravatarEnumTargetList / gravatarEnumGenerate
//
// 10T-535 (5/8): gravatarEnumTargets() ([]string, error) is retargeted onto
// gravatarEnumTargetList() ([]enum.Target, error) — the Target-returning
// function that carries each generated address's name (mirrors
// googleEnumTargetList / githubEnumTargetList). gravatarEnumGenerate() is
// retargeted from ([]string, error) to ([]enum.Target, error) for the same
// reason. Every prior assertion (trim, case-insensitive dedup, "provide"
// error, --limit capping, invalid-format error) is preserved; there is no
// dead adapter left behind pinning the old []string signatures.
// ---------------------------------------------------------------------------

func resetGravatarEnumFlags() (restore func()) {
	origEmails := flagGravatarEnumEmails
	origEmailFile := flagGravatarEnumEmailFile
	origDomain := flagGravatarEnumDomain
	origFormat := flagGravatarEnumFormat
	origLimit := flagGravatarEnumLimit
	return func() {
		flagGravatarEnumEmails = origEmails
		flagGravatarEnumEmailFile = origEmailFile
		flagGravatarEnumDomain = origDomain
		flagGravatarEnumFormat = origFormat
		flagGravatarEnumLimit = origLimit
	}
}

// TestGravatarEnumTargetList_InlineEmails verifies that --emails CSV is parsed,
// trimmed, lower-cased, and deduplicated (case-insensitively), and that every
// CLI-supplied target carries no name (a supplied address says nothing about
// whose it is) — mirrors TestGoogleEnumTargetList_InlineEmails /
// TestGithubEnumTargetList equivalents.
func TestGravatarEnumTargetList_InlineEmails(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = "Alice@Example.com, Bob@Example.com ,alice@example.com"
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	// Deduplication (case-insensitive) and lower-casing/trimming: Alice and
	// alice must collapse to one lower-cased, trimmed entry.
	assert.Len(t, emails, 2, "deduplication must collapse case-insensitive duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")

	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestGravatarEnumTargetList_CaseInsensitiveDedup pins the specific example
// called out for PR5: A@x.com and a@x.com must collapse to a single
// lower-cased entry.
func TestGravatarEnumTargetList_CaseInsensitiveDedup(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = "A@x.com,a@x.com"
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)

	emails := enumTargetEmails(got)
	require.Len(t, emails, 1, "A@x.com and a@x.com must collapse to a single entry")
	assert.Equal(t, "a@x.com", emails[0], "the surviving entry must be lower-cased")
	assert.Empty(t, got[0].First, "the surviving CLI-supplied entry must carry no name")
	assert.Empty(t, got[0].Last, "the surviving CLI-supplied entry must carry no name")
}

// TestGravatarEnumTargetList_NoSource verifies that an error is returned (and
// mentions "provide") when no --emails, --email-file, or --domain is given.
func TestGravatarEnumTargetList_NoSource(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = ""
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	_, err := gravatarEnumTargetList()
	require.Error(t, err, "gravatarEnumTargetList must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error message must guide the user to supply a target source")
}

// TestGravatarEnumTargetList_DomainGeneratedCarriesName verifies that
// --domain-generated targets carry the non-empty First/Last the username was
// built from, unlike CLI-supplied addresses, and that --limit caps the count.
func TestGravatarEnumTargetList_DomainGeneratedCarriesName(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = ""
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 5

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 5, "--limit must cap the number of generated targets")

	for i, target := range got {
		assert.Contains(t, target.Email, "@target.com", "target %d must be for the requested domain", i)
		assert.NotEmpty(t, target.First, "target %d (%q): a --domain-generated target must carry a non-empty First", i, target.Email)
		assert.NotEmpty(t, target.Last, "target %d (%q): a --domain-generated target must carry a non-empty Last", i, target.Email)
	}
}

// ---------------------------------------------------------------------------
// THE CRITICAL TRAP (10T-535, 5/8)
//
// cmd_enum_gravatar.go's target-building/dedup loop (formerly line ~196 of
// gravatarEnumTargets, now inside gravatarEnumTargetList) lower-cases every
// address: e = strings.ToLower(strings.TrimSpace(e)). That normalization must
// land on the Target's Email FIELD itself — the exact address that
// enumTargetEmails() hands to gravatar.Checker.EnumerateWith and that
// gravatar.CheckAccount echoes back verbatim on Result.Email (CheckAccount
// never re-cases the address it is given; it only lower-cases a COPY for
// HashEmail's MD5 digest).
//
// If the loop normalizes a throwaway local variable (e.g. only the key used
// for the dedup "seen" set) but appends the ORIGINAL, un-normalized Candidate
// address onto the returned Target, then any code path that independently
// re-derives the checker's input by re-normalizing (rather than reusing
// enumTargetEmails on the same targets slice) will diverge from the
// un-normalized Target.Email that enumNamesByEmail indexes by. The generated
// name then vanishes silently on lookup: no error, no warning, just no name
// in the output.
//
// This test generates with a MIXED-CASE --domain ("Example.COM") and asserts:
//  1. Every returned Target's Email is already lower-cased (the domain's
//     mixed case must not survive into Target.Email).
//  2. Every generated target's name is recoverable via enumNamesByEmail +
//     enumNameFor, keyed on the address gravatar.Checker will actually
//     receive and echo back (target.Email itself, and independently its
//     lower-cased form — asserting these are identical is exactly the
//     invariant the fix must hold).
// ---------------------------------------------------------------------------

func TestGravatarEnumTargetList_GeneratedAddressesAreLowerCasedForNameLookup(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = ""
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = "Example.COM" // mixed-case domain: the trap.
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 10

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)
	require.Len(t, got, 10, "--limit must cap the number of generated targets")

	for i, target := range got {
		// The address stored on the Target must ALREADY be lower-cased: this is
		// the exact address enumTargetEmails() will hand to
		// gravatar.Checker.EnumerateWith, and CheckAccount echoes back the
		// address it is given verbatim on Result.Email.
		lowered := strings.ToLower(strings.TrimSpace(target.Email))
		require.Equal(t, lowered, target.Email,
			"target %d: Target.Email must already be lower-cased/trimmed inside gravatarEnumTargetList's target-building loop, matching what gravatar.CheckAccount will echo back on Result.Email", i)
		require.NotContains(t, target.Email, "Example.COM",
			"target %d (%q): Target.Email must not retain the mixed-case domain the operator supplied via --domain — the merge loop's lower-casing must apply to the Target field itself, not just a discarded local variable", i, target.Email)
	}

	// enumNamesByEmail/enumNameFor are the shared framework helpers (unmodified,
	// reused from cmd_enum.go) that runEnumGravatar wires up exactly like
	// runEnumGoogle/runEnumGithub: names := enumNamesByEmail(targets), then each
	// onResult callback does res.First, res.Last = enumNameFor(names, res.Email).
	// Building the index from the SAME already-normalized targets slice that
	// gravatarEnumTargetList returned is what keeps the lookup key
	// byte-identical to the address the checker echoes back.
	names := enumNamesByEmail(got)
	require.Len(t, names, len(got), "every generated target must be indexed by enumNamesByEmail")

	for i, target := range got {
		// Simulate the checker echoing the address back on a Result: gravatar's
		// CheckAccount sets Result{Email: email} verbatim from the email
		// parameter it is given, which is target.Email itself.
		echoedByChecker := target.Email

		first, last := enumNameFor(names, echoedByChecker)
		assert.NotEmpty(t, first,
			"target %d (%q): name lookup keyed on the checker-echoed (lower-cased) address must recover a non-empty First — an empty result here means the index was built on an un-normalized address and the name silently vanished", i, target.Email)
		assert.NotEmpty(t, last,
			"target %d (%q): name lookup keyed on the checker-echoed (lower-cased) address must recover a non-empty Last — an empty result here means the index was built on an un-normalized address and the name silently vanished", i, target.Email)
		assert.Equal(t, target.First, first, "target %d: recovered First must match the target's own First", i)
		assert.Equal(t, target.Last, last, "target %d: recovered Last must match the target's own Last", i)

		// The lookup must also succeed when keyed by the independently
		// lower-cased form of the address — proving the stored key and the
		// checker-echoed address are byte-identical, not just coincidentally
		// equal in this test's construction.
		independentlyLowered := strings.ToLower(strings.TrimSpace(target.Email))
		firstAgain, lastAgain := enumNameFor(names, independentlyLowered)
		assert.Equal(t, first, firstAgain,
			"target %d: lookup keyed on the independently-lower-cased address must match the lookup keyed on target.Email itself", i)
		assert.Equal(t, last, lastAgain,
			"target %d: lookup keyed on the independently-lower-cased address must match the lookup keyed on target.Email itself", i)
	}
}

// ---------------------------------------------------------------------------
// gravatarEnumGenerate
// ---------------------------------------------------------------------------

func TestGravatarEnumGenerate_ProducesCandidatesForDomain(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 0

	generated, err := gravatarEnumGenerate()
	require.NoError(t, err)

	candidates, err := enum.GenerateCandidates("first.last")
	require.NoError(t, err)

	want := make([]enum.Target, len(candidates))
	for i, c := range candidates {
		want[i] = c.Target("target.com")
	}

	assert.Equal(t, want, generated,
		"gravatarEnumGenerate must reuse enum.GenerateCandidates (via capResults and Candidate.Target), matching the google/github generate pattern")
	for i, target := range generated {
		assert.Contains(t, target.Email, "@target.com", "target %d must be for the requested domain", i)
		assert.NotEmpty(t, target.First, "target %d: generated target must carry a non-empty First", i)
		assert.NotEmpty(t, target.Last, "target %d: generated target must carry a non-empty Last", i)
	}
}

func TestGravatarEnumGenerate_RespectsLimit(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 3

	generated, err := gravatarEnumGenerate()
	require.NoError(t, err)

	assert.Len(t, generated, 3, "--limit must cap the number of generated candidates")

	candidates, err := enum.GenerateCandidates("first.last")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(candidates), 3, "full generated list must have at least 3 candidates for this assertion to be meaningful")

	want := make([]enum.Target, 3)
	for i := 0; i < 3; i++ {
		want[i] = candidates[i].Target("target.com")
	}
	assert.Equal(t, want, generated, "--limit must keep the first (most-likely) N candidates")
}

func TestGravatarEnumGenerate_InvalidFormatRejected(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "not-a-real-format"
	flagGravatarEnumLimit = 0

	_, err := gravatarEnumGenerate()
	require.Error(t, err, "an invalid --format must be rejected")
	assert.Contains(t, err.Error(), "invalid --format")
}

// ---------------------------------------------------------------------------
// outputGravatarEnumJSONL — First/Last name propagation (10T-535, 5/8)
// ---------------------------------------------------------------------------

// TestOutputGravatarEnumJSONL_NameFields pins the never-invent-a-name rule: a
// Result carrying First/Last (from --domain generation) must emit
// "first"/"last" in the JSONL row, while a Result with empty First/Last
// (supplied via --emails or --email-file) must OMIT both keys entirely rather
// than emit them as "". Pre-existing fields (email/hash/exists/avatar_url)
// must be unaffected by the addition — mirrors
// TestOutputGoogleEnumJSONL_NameFields.
func TestOutputGravatarEnumJSONL_NameFields(t *testing.T) {
	named := gravatar.Result{
		Email:  "john.smith@example.com",
		Hash:   gravatar.HashEmail("john.smith@example.com"),
		Exists: true,
		First:  "john",
		Last:   "smith",
	}
	unnamed := gravatar.Result{
		Email:  "supplied@example.com",
		Hash:   gravatar.HashEmail("supplied@example.com"),
		Exists: true,
	}

	t.Run("named result emits first and last", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{named})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGravatarEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.Equal(t, "john", obj["first"], `first field must be "john"`)
		assert.Equal(t, "smith", obj["last"], `last field must be "smith"`)

		// Pre-existing fields must remain unaffected by the new ones.
		assert.Equal(t, named.Email, obj["email"])
		assert.Equal(t, named.Hash, obj["hash"], "hash field must be unaffected by first/last")
		assert.Equal(t, true, obj["exists"])
		assert.Equal(t, fmt.Sprintf("https://www.gravatar.com/avatar/%s", named.Hash), obj["avatar_url"])
	})

	t.Run("unnamed result omits first and last keys", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{unnamed})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGravatarEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.NotContains(t, obj, "first",
			`first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last",
			`last key must be absent (omitempty), not emitted as ""`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, unnamed.Email, obj["email"])
		assert.Equal(t, unnamed.Hash, obj["hash"], "hash field must be unaffected by first/last")
		assert.Equal(t, true, obj["exists"])
	})

	t.Run("mixed batch: one named, one unnamed", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{named, unnamed})

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 2, "must emit exactly one JSONL line per result")

		var first map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
		assert.Equal(t, "john", first["first"])
		assert.Equal(t, "smith", first["last"])

		var second map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
		assert.NotContains(t, second, "first",
			`second (unnamed) line must not carry a "first" key`)
		assert.NotContains(t, second, "last",
			`second (unnamed) line must not carry a "last" key`)
	})
}
