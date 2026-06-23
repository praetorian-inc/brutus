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

package enum

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxWordlistSize is the documented upper bound of the likely-names wordlist.
// Tests assert len(result) <= this bound rather than an exact count so they
// stay valid if the wordlist is ever updated.
const maxWordlistSize = 248231

// ---------------------------------------------------------------------------
// TestGenerateUsernames_FirstDotLast
// ---------------------------------------------------------------------------

// TestGenerateUsernames_FirstDotLast verifies that the first.last format
// produces a non-empty, bounded, frequency-ranked result set whose head
// entries match the expected most-likely pairs from the wordlist.
func TestGenerateUsernames_FirstDotLast(t *testing.T) {
	t.Parallel()

	result, err := GenerateUsernames(FormatFirstDotLast)
	require.NoError(t, err)

	// Non-empty and bounded.
	require.NotEmpty(t, result, "first.last must produce at least one username")
	assert.LessOrEqual(t, len(result), maxWordlistSize,
		"result length must not exceed the wordlist size")

	// Ranked order: john.smith is the most-likely pair and must be index 0.
	assert.Equal(t, "john.smith", result[0],
		"john.smith must be the first first.last entry (most-likely ranked)")

	// The wordlist is ordered most-likely-first; the next two known high-rank
	// entries must appear early in the list.
	top5 := make(map[string]bool)
	for _, u := range result[:min(5, len(result))] {
		top5[u] = true
	}
	assert.True(t, top5["david.smith"] || top5["michael.smith"],
		"david.smith or michael.smith must appear in the top 5 first.last entries")
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_DerivedFormats
// ---------------------------------------------------------------------------

// TestGenerateUsernames_DerivedFormats verifies that each format derives its
// first entry from the #1 ranked pair (john.smith → first=john, last=smith).
func TestGenerateUsernames_DerivedFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format    string
		wantFirst string
	}{
		{FormatFLast, "jsmith"},
		{FormatFirstL, "johns"},
		{FormatFDotLast, "j.smith"},
		{FormatLastF, "smithj"},
		{FormatLastDotFirst, "smith.john"},
		{FormatLastFirst, "smithjohn"},
		{FormatFirst, "john"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.format, func(t *testing.T) {
			t.Parallel()

			result, err := GenerateUsernames(tc.format)
			require.NoError(t, err, "format %q must not error", tc.format)
			require.NotEmpty(t, result, "format %q must produce at least one entry", tc.format)

			// Report actual value on mismatch to aid debugging rather than
			// forcing an assertion that could be brittle.
			if result[0] != tc.wantFirst {
				t.Logf("format %q: wanted first entry %q, got %q — updating expectation",
					tc.format, tc.wantFirst, result[0])
			}
			assert.Equal(t, tc.wantFirst, result[0],
				"format %q: first entry must be derived from the #1 ranked pair (john.smith)",
				tc.format)
		})
	}
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_Dedup
// ---------------------------------------------------------------------------

// TestGenerateUsernames_Dedup verifies that formats that collapse many source
// pairs to the same output (e.g. "first" produces "john" from every
// "john.*" pair) correctly deduplicate while preserving ranked first-occurrence
// order, and that deduplicated results are strictly smaller than the raw pair
// count.
func TestGenerateUsernames_Dedup(t *testing.T) {
	t.Parallel()

	t.Run("flast_deduped", func(t *testing.T) {
		t.Parallel()

		result, err := GenerateUsernames(FormatFLast)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		// Deduplicated result must be smaller than the full wordlist.
		assert.Less(t, len(result), maxWordlistSize,
			"flast result must be deduplicated (smaller than wordlist)")

		// No duplicate entries.
		seen := make(map[string]bool, len(result))
		for _, u := range result {
			assert.False(t, seen[u], "duplicate entry found in flast results: %q", u)
			seen[u] = true
		}
	})

	t.Run("first_deduped_to_few_thousand", func(t *testing.T) {
		t.Parallel()

		result, err := GenerateUsernames(FormatFirst)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		// "first" collapses hundreds of john.* pairs to a single "john",
		// so the deduplicated count should be in the thousands, not hundreds
		// of thousands.
		assert.Less(t, len(result), 100_000,
			"first format should produce far fewer unique values than the raw wordlist")

		// No duplicate entries.
		seen := make(map[string]bool, len(result))
		for _, u := range result {
			assert.False(t, seen[u], "duplicate entry found in first results: %q", u)
			seen[u] = true
		}
	})
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_MultiPartSurnames
// ---------------------------------------------------------------------------

// TestGenerateUsernames_MultiPartSurnames verifies that multi-dot source lines
// are handled correctly. For first.last format the full dotted name is
// preserved; for concatenated formats dots are stripped.
func TestGenerateUsernames_MultiPartSurnames(t *testing.T) {
	t.Parallel()

	t.Run("first_dot_last_has_dots", func(t *testing.T) {
		t.Parallel()

		result, err := GenerateUsernames(FormatFirstDotLast)
		require.NoError(t, err)

		// Every entry in first.last must contain at least one dot (the separator
		// between first and last components).
		for _, u := range result {
			assert.Contains(t, u, ".", "every first.last entry must contain a dot: %q", u)
		}
	})

	// Formats that concatenate (no dots expected in output).
	noDotFormats := []string{
		FormatFLast,
		FormatFirstL,
		FormatLastF,
		FormatLastFirst,
		FormatFirst,
	}

	for _, format := range noDotFormats {
		format := format
		t.Run(format+"_no_dots", func(t *testing.T) {
			t.Parallel()

			result, err := GenerateUsernames(format)
			require.NoError(t, err)

			for _, u := range result {
				assert.False(t, strings.Contains(u, "."),
					"format %q must not contain dots (multi-part surname dots stripped): got %q",
					format, u)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_AllFormatsBoundedAndNonEmpty
// ---------------------------------------------------------------------------

// TestGenerateUsernames_AllFormatsBoundedAndNonEmpty is a table-driven test
// that verifies every supported format produces a non-empty, bounded result
// with no empty-string entries and all-lowercase output.
func TestGenerateUsernames_AllFormatsBoundedAndNonEmpty(t *testing.T) {
	t.Parallel()

	formats := ListFormats()
	require.Len(t, formats, 8, "ListFormats must return exactly 8 formats")

	for _, format := range formats {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			result, err := GenerateUsernames(format)
			require.NoError(t, err, "format %q must not error", format)
			require.NotEmpty(t, result, "format %q must produce at least one entry", format)

			assert.LessOrEqual(t, len(result), maxWordlistSize,
				"format %q result length must not exceed wordlist size", format)

			for i, u := range result {
				assert.NotEmpty(t, u, "format %q: entry at index %d must not be empty", format, i)
				assert.Equal(t, strings.ToLower(u), u,
					"format %q: entry %q must be all lowercase", format, u)
				// Verify no non-printable / whitespace characters sneak in.
				for _, r := range u {
					assert.False(t, unicode.IsSpace(r),
						"format %q: entry %q contains whitespace rune %q", format, u, r)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_UnknownFormat
// ---------------------------------------------------------------------------

// TestGenerateUsernames_UnknownFormat verifies that an unrecognised format
// string causes all pairs to be skipped (formatUsername returns "" for the
// default branch), producing an empty result with no error.
func TestGenerateUsernames_UnknownFormat(t *testing.T) {
	t.Parallel()

	result, err := GenerateUsernames("totally-unknown-format")
	require.NoError(t, err, "unknown format must not produce an error")
	assert.Empty(t, result,
		"unknown format must produce an empty result (formatUsername default branch returns \"\")")
}

// ---------------------------------------------------------------------------
// TestGenerateEmails
// ---------------------------------------------------------------------------

// TestGenerateEmails verifies that GenerateEmails appends @domain to each
// username and produces the same count as the corresponding GenerateUsernames
// call.
func TestGenerateEmails(t *testing.T) {
	t.Parallel()

	const domain = "fox.com"

	emails, err := GenerateEmails(FormatFirstDotLast, domain)
	require.NoError(t, err)
	require.NotEmpty(t, emails)

	// First entry must be the highest-ranked pair with @domain appended.
	assert.Equal(t, "john.smith@fox.com", emails[0],
		"first email must be john.smith@fox.com")

	// Every entry must end with @domain.
	suffix := "@" + domain
	for i, e := range emails {
		assert.True(t, strings.HasSuffix(e, suffix),
			"email at index %d (%q) must end with %q", i, e, suffix)
	}

	// Count must match the corresponding username generation.
	usernames, err := GenerateUsernames(FormatFirstDotLast)
	require.NoError(t, err)
	assert.Equal(t, len(usernames), len(emails),
		"GenerateEmails must produce the same count as GenerateUsernames for the same format")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
