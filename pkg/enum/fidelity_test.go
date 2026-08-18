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

// Tests for per-format field fidelity: how much of a name the generated
// username actually proves. The generator holds the full "first.last" pair it
// built each username from, but a lossy format discards part of it -- "jsmith"
// proves only that the given name starts with J. Consumers that label a
// confirmed hit with a person's name must reduce the carried pair to what the
// address demonstrates, and that reduction is a pure function of the format.
//
// These tests pin the mapping for EVERY format in ListFormats, so adding a
// format without deciding its fidelity fails here rather than silently
// defaulting to a guess.
package enum

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFormatFidelity_EveryFormatMapped is the guard against a new format
// slipping in without a fidelity decision. FormatFidelity must not report
// FieldAbsent for the first name of any real format -- every format in the set
// encodes at least the given name's initial.
func TestFormatFidelity_EveryFormatMapped(t *testing.T) {
	for _, format := range ListFormats() {
		t.Run(format, func(t *testing.T) {
			first, last := FormatFidelity(format)
			assert.NotEqual(t, FieldAbsent, first,
				"every supported format encodes at least the first initial; %q reports the given name absent, which likely means FormatFidelity was never taught about it", format)
			assert.Contains(t, []FieldFidelity{FieldAbsent, FieldInitial, FieldExact}, last,
				"surname fidelity must be one of the three defined states")
		})
	}
}

func TestFormatFidelity_Mapping(t *testing.T) {
	tests := []struct {
		format string
		first  FieldFidelity
		last   FieldFidelity
		why    string
	}{
		// Separator-delimited, both parts present: unambiguous.
		{FormatFirstDotLast, FieldExact, FieldExact, "john.smith encodes both parts, dot-delimited"},
		{FormatLastDotFirst, FieldExact, FieldExact, "smith.john encodes both parts, dot-delimited"},
		{FormatFirstUnderLast, FieldExact, FieldExact, "john_smith encodes both parts, underscore-delimited"},

		// No separator, but both parts are present in full. The boundary is not
		// recoverable from the string in principle; measured against the shipped
		// wordlist only 6 of 248,093 lastfirst usernames have an ambiguous split
		// (0.00%, worst case "limandy" = Andy Lim or Mandy Li), so this is
		// treated as exact rather than warranting a fourth fidelity state.
		{FormatLastFirst, FieldExact, FieldExact, "smithjohn carries both parts in full"},

		// Given name truncated to its initial.
		{FormatFLast, FieldInitial, FieldExact, "jsmith proves only J"},
		{FormatFDotLast, FieldInitial, FieldExact, "j.smith proves only J"},
		{FormatLastF, FieldInitial, FieldExact, "smithj proves only J"},

		// Surname truncated to its initial -- the given name survives intact.
		{FormatFirstL, FieldExact, FieldInitial, "johns proves John but only S"},

		// No surname in the address at all.
		{FormatFirst, FieldExact, FieldAbsent, "john encodes no surname whatsoever"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			first, last := FormatFidelity(tt.format)
			assert.Equal(t, tt.first, first, "first name fidelity: %s", tt.why)
			assert.Equal(t, tt.last, last, "surname fidelity: %s", tt.why)
		})
	}
}

// TestFormatFidelity_UnknownFormatIsAbsent pairs with GenerateCandidates, which
// yields nothing for an unrecognized format. Reporting Absent/Absent means a
// consumer that somehow reaches KnownName with a bogus format emits no name
// rather than a name it cannot justify.
func TestFormatFidelity_UnknownFormatIsAbsent(t *testing.T) {
	first, last := FormatFidelity("totally-unknown-format")
	assert.Equal(t, FieldAbsent, first)
	assert.Equal(t, FieldAbsent, last)

	kf, kl := KnownName("totally-unknown-format", "John", "Smith")
	assert.Empty(t, kf, "an unknown format must not license a name")
	assert.Empty(t, kl)
}

func TestKnownName_ReducesToWhatTheAddressProves(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		first, last string
		wantFirst   string
		wantLast    string
	}{
		{"first.last keeps both", FormatFirstDotLast, "John", "Smith", "John", "Smith"},
		{"last.first keeps both", FormatLastDotFirst, "John", "Smith", "John", "Smith"},
		{"first_last keeps both", FormatFirstUnderLast, "John", "Smith", "John", "Smith"},
		{"lastfirst keeps both", FormatLastFirst, "John", "Smith", "John", "Smith"},

		// The headline case: jsmith@example.com is "J Smith", never "John Smith".
		{"flast truncates the given name", FormatFLast, "John", "Smith", "J", "Smith"},
		{"f.last truncates the given name", FormatFDotLast, "James", "Smith", "J", "Smith"},
		{"lastf truncates the given name", FormatLastF, "Jason", "Smith", "J", "Smith"},

		{"firstl truncates the surname", FormatFirstL, "John", "Smith", "John", "S"},

		// john@example.com contains no surname, so the wordlist's surname for
		// the highest-ranked "john.*" pair must not leak out as a fact.
		{"first drops the surname entirely", FormatFirst, "John", "Smith", "John", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirst, gotLast := KnownName(tt.format, tt.first, tt.last)
			assert.Equal(t, tt.wantFirst, gotFirst)
			assert.Equal(t, tt.wantLast, gotLast)
		})
	}
}

// TestKnownName_InitialMatchesTheGeneratedUsername is the correctness anchor:
// the initial KnownName reports must be the same character formatUsername
// actually put into the address. If those two ever disagree we would be
// reporting an initial the address does not contain.
func TestKnownName_InitialMatchesTheGeneratedUsername(t *testing.T) {
	const first, last = "john", "smith"

	for _, format := range []string{FormatFLast, FormatFDotLast, FormatLastF} {
		t.Run(format, func(t *testing.T) {
			username := formatUsername(first, last, format)
			require.NotEmpty(t, username)

			knownFirst, _ := KnownName(format, first, last)
			require.Len(t, knownFirst, 1)
			assert.Contains(t, username, knownFirst,
				"the reported initial %q must appear in the username %q it came from", knownFirst, username)
			assert.Equal(t, first[:1], knownFirst,
				"formatUsername uses first[:1]; KnownName must report that same character")
		})
	}

	t.Run(FormatFirstL, func(t *testing.T) {
		username := formatUsername(first, last, FormatFirstL)
		require.NotEmpty(t, username)

		_, knownLast := KnownName(FormatFirstL, first, last)
		require.Len(t, knownLast, 1)
		assert.Equal(t, last[:1], knownLast,
			"formatUsername uses lastConcat[:1]; KnownName must report that same character")
	})
}

// TestKnownName_EmptyInputDoesNotPanic covers the slicing hazard: reducing a
// field to its initial means taking the first character of a string that may be
// empty.
func TestKnownName_EmptyInputDoesNotPanic(t *testing.T) {
	for _, format := range ListFormats() {
		t.Run(format, func(t *testing.T) {
			assert.NotPanics(t, func() {
				gotFirst, gotLast := KnownName(format, "", "")
				assert.Empty(t, gotFirst)
				assert.Empty(t, gotLast)
			})
		})
	}
}

// TestKnownName_InitialIsRuneSafe documents a divergence rather than asserting
// parity. Every pair in the shipped wordlist is ASCII, so formatUsername's
// byte-slicing first[:1] is safe for generated candidates. KnownName is
// exported and may be called with arbitrary input, where byte-slicing a
// multi-byte rune would emit an invalid UTF-8 fragment, so it slices by rune.
func TestKnownName_InitialIsRuneSafe(t *testing.T) {
	knownFirst, knownLast := KnownName(FormatFLast, "Ángel", "Ruiz")
	assert.Equal(t, "Á", knownFirst, "must be a whole rune, not a truncated byte")
	assert.Equal(t, "Ruiz", knownLast)

	_, surname := KnownName(FormatFirstL, "Ana", "Île")
	assert.Equal(t, "Î", surname)
}

// TestKnownName_UndecodableInitialIsDropped is the other half of rune safety.
// An input that is not valid UTF-8 has no meaningful first character, and
// returning its leading byte would put an invalid string into a Person record.
// Dropping it is the only option that cannot produce broken output.
func TestKnownName_UndecodableInitialIsDropped(t *testing.T) {
	knownFirst, knownLast := KnownName(FormatFLast, "\xffbroken", "Smith")
	assert.Empty(t, knownFirst, "an undecodable byte must not be reported as an initial")
	assert.Equal(t, "Smith", knownLast, "the exact field is passed through untouched, valid or not")

	assert.True(t, utf8.ValidString(knownFirst), "output must always be valid UTF-8")
}

// TestKnownName_DoesNotTitleCaseOrTrim keeps the reduction a pure projection.
// Casing is the consumer's presentation concern (guard has personname.TitleCase
// for it); silently title-casing here would make KnownName's output disagree
// with the Candidate fields it derives from.
func TestKnownName_DoesNotTitleCaseOrTrim(t *testing.T) {
	first, last := KnownName(FormatFirstDotLast, "john", "smith")
	assert.Equal(t, "john", first, "casing is the consumer's concern")
	assert.Equal(t, "smith", last)

	initial, _ := KnownName(FormatFLast, "john", "smith")
	assert.Equal(t, "j", initial, "the initial keeps the case it was given")
}

func TestFieldFidelity_String(t *testing.T) {
	assert.Equal(t, "absent", FieldAbsent.String())
	assert.Equal(t, "initial", FieldInitial.String())
	assert.Equal(t, "exact", FieldExact.String())
	assert.Equal(t, "unknown", FieldFidelity(99).String())
}
