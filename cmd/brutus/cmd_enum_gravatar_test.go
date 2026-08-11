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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// TestGravatarEnumTargetList
//
// 10T-535: gravatarEnumTargets() ([]string, error) and gravatarEnumGenerate()
// ([]string, error) were dead []string adapters kept alive only by these
// tests (the real logic — and the only production callers, runEnumGravatar
// — lives in gravatarEnumTargetList() and gravatarEnumGenerateTargets(),
// both returning ([]enum.Target, error)). Retargeted onto those and
// strengthened to assert that supplied (--emails/--email-file) targets carry
// no name while generated ones do, using the targetEmails helper from
// cmd_enum_custom_test.go for compact address assertions. Exercises
// gravatarEnumTargetList()/gravatarEnumGenerateTargets() using the
// file-local flag variables directly, saving and restoring them with defer
// (mirrors TestGoogleEnumTargetList_InlineEmails).
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

func TestGravatarEnumTargetList_InlineEmails(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = "Alice@Example.com, Bob@Example.com ,alice@example.com"
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)

	emails := targetEmails(got)
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

// ---------------------------------------------------------------------------
// TestGravatarEnumGenerateTargets
// ---------------------------------------------------------------------------

func TestGravatarEnumGenerateTargets_ProducesCandidatesForDomain(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 0

	got, err := gravatarEnumGenerateTargets()
	require.NoError(t, err)

	wantEmails, err := enum.GenerateEmails("first.last", "target.com")
	require.NoError(t, err)

	generated := targetEmails(got)
	assert.Equal(t, wantEmails, generated,
		"gravatarEnumGenerateTargets must reuse enum.GenerateEmails/GenerateCandidates and return the same candidate addresses")
	for i, target := range got {
		assert.Contains(t, target.Email, "@target.com", "every generated candidate must be for the requested domain")
		require.NotEmpty(t, target.First, "target %d (%q): generated candidate must have non-empty First", i, target.Email)
		require.NotEmpty(t, target.Last, "target %d (%q): generated candidate must have non-empty Last", i, target.Email)
	}
}

func TestGravatarEnumGenerateTargets_RespectsLimit(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 3

	got, err := gravatarEnumGenerateTargets()
	require.NoError(t, err)

	assert.Len(t, got, 3, "--limit must cap the number of generated candidates")

	wantEmails, err := enum.GenerateEmails("first.last", "target.com")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(wantEmails), 3, "full generated list must have at least 3 candidates for this assertion to be meaningful")
	assert.Equal(t, wantEmails[:3], targetEmails(got), "--limit must keep the first (most-likely) N candidates")
}

func TestGravatarEnumGenerateTargets_InvalidFormatRejected(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "not-a-real-format"
	flagGravatarEnumLimit = 0

	_, err := gravatarEnumGenerateTargets()
	require.Error(t, err, "an invalid --format must be rejected")
	assert.Contains(t, err.Error(), "invalid --format")
}

// TestGravatarEnumTargetList_NamesSurviveLowerCasing pins a normalization
// behavior the developer found a real bug in: gravatar lower-cases every
// address (see gravatarEnumTargetList — unlike microsoft365, this is the
// FULL address, not just the dedup key), because Gravatar hashing and the
// avatar-existence check are both case-insensitive. The name-lookup helpers
// (enumNamesByEmail/enumNameFor) key on the exact target Email, so this test
// proves the index key gravatarEnumTargetList produces is exactly the
// lower-cased address that enumTargetEmails hands to the checker — a
// mismatch here would silently drop every generated name.
func TestGravatarEnumTargetList_NamesSurviveLowerCasing(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = ""
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = "Target.com" // mixed case, as an operator might type it
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 5

	got, err := gravatarEnumTargetList()
	require.NoError(t, err)
	require.NotEmpty(t, got)

	for i, target := range got {
		// Gravatar lower-cases the FULL address, domain included — not just the
		// dedup key — so the mixed-case --domain must not survive on Email.
		assert.Equal(t, strings.ToLower(target.Email), target.Email,
			"target %d: gravatar target Email must be fully lower-cased, got %q", i, target.Email)
		require.NotEmpty(t, target.First, "target %d (%q): generated target must have non-empty First", i, target.Email)
		require.NotEmpty(t, target.Last, "target %d (%q): generated target must have non-empty Last", i, target.Email)
	}

	// The real production round trip: the emails handed to the checker
	// (enumTargetEmails) must be exactly the lower-cased addresses stored on
	// each target, and enumNamesByEmail/enumNameFor must resolve each one back
	// to its name by that same lower-cased key.
	emails := enumTargetEmails(got)
	names := enumNamesByEmail(got)
	for i, target := range got {
		assert.Equal(t, target.Email, emails[i], "target %d: enumTargetEmails must hand the checker the exact stored (lower-cased) Email", i)
		first, last := enumNameFor(names, emails[i])
		assert.Equal(t, target.First, first, "target %d (%q): name lookup by the lower-cased address handed to the checker must find First", i, target.Email)
		assert.Equal(t, target.Last, last, "target %d (%q): name lookup by the lower-cased address handed to the checker must find Last", i, target.Email)
	}
}
