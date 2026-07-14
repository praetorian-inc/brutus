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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// TestGravatarEnumTargets
// Exercises gravatarEnumTargets() using the file-local flag variables
// directly, saving and restoring them with defer (mirrors
// TestGoogleEnumTargets_InlineEmails).
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

func TestGravatarEnumTargets_InlineEmails(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = "Alice@Example.com, Bob@Example.com ,alice@example.com"
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	emails, err := gravatarEnumTargets()
	require.NoError(t, err)

	// Deduplication (case-insensitive) and lower-casing/trimming: Alice and
	// alice must collapse to one lower-cased, trimmed entry.
	assert.Len(t, emails, 2, "deduplication must collapse case-insensitive duplicate emails")
	assert.Contains(t, emails, "alice@example.com")
	assert.Contains(t, emails, "bob@example.com")
}

func TestGravatarEnumTargets_NoSource(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumEmails = ""
	flagGravatarEnumEmailFile = ""
	flagGravatarEnumDomain = ""

	_, err := gravatarEnumTargets()
	require.Error(t, err, "gravatarEnumTargets must fail when no source is supplied")
	assert.Contains(t, err.Error(), "provide",
		"error message must guide the user to supply a target source")
}

// ---------------------------------------------------------------------------
// TestGravatarEnumGenerate
// ---------------------------------------------------------------------------

func TestGravatarEnumGenerate_ProducesCandidatesForDomain(t *testing.T) {
	defer resetGravatarEnumFlags()()

	flagGravatarEnumDomain = "target.com"
	flagGravatarEnumFormat = "first.last"
	flagGravatarEnumLimit = 0

	generated, err := gravatarEnumGenerate()
	require.NoError(t, err)

	want, err := enum.GenerateEmails("first.last", "target.com")
	require.NoError(t, err)

	assert.Equal(t, want, generated,
		"gravatarEnumGenerate must reuse enum.GenerateEmails and return the same candidates")
	for _, e := range generated {
		assert.Contains(t, e, "@target.com", "every generated candidate must be for the requested domain")
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

	want, err := enum.GenerateEmails("first.last", "target.com")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(want), 3, "full generated list must have at least 3 candidates for this assertion to be meaningful")
	assert.Equal(t, want[:3], generated, "--limit must keep the first (most-likely) N candidates")
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
