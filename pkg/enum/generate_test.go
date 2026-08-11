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
		{FormatFirstUnderLast, "john_smith"},
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
		FormatFirstUnderLast,
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
	require.Len(t, formats, 9, "ListFormats must return exactly 9 formats")

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

// TestGenerateUsernames_UnknownFormat verifies that an unrecognized format
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
// TestListFormats_IncludesFirstUnderLast
// ---------------------------------------------------------------------------

// TestListFormats_IncludesFirstUnderLast verifies that ListFormats includes the
// "first_last" format constant.
func TestListFormats_IncludesFirstUnderLast(t *testing.T) {
	t.Parallel()

	formats := ListFormats()
	assert.Contains(t, formats, FormatFirstUnderLast,
		"ListFormats must include FormatFirstUnderLast (%q)", FormatFirstUnderLast)
}

// ---------------------------------------------------------------------------
// TestGenerateUsernames_FirstUnderLast
// ---------------------------------------------------------------------------

// TestGenerateUsernames_FirstUnderLast verifies all structural properties of
// the first_last format: ranked head entry, underscore separator, no dots,
// all-lowercase, deduplication, and bounds.
func TestGenerateUsernames_FirstUnderLast(t *testing.T) {
	t.Parallel()

	result, err := GenerateUsernames(FormatFirstUnderLast)
	require.NoError(t, err)

	// Non-empty and bounded.
	require.NotEmpty(t, result, "first_last must produce at least one username")
	assert.LessOrEqual(t, len(result), maxWordlistSize,
		"first_last result length must not exceed the wordlist size")

	// Ranked head: john.smith → john_smith.
	// Report actual value rather than force-failing if the wordlist ever changes.
	if result[0] != "john_smith" {
		t.Logf("first_last: expected first entry %q, got %q — reporting actual value",
			"john_smith", result[0])
	}
	assert.Equal(t, "john_smith", result[0],
		"first_last: first entry must be derived from the #1 ranked pair (john.smith)")

	// Every entry must contain exactly one underscore and no dots.
	for _, u := range result {
		assert.Equal(t, 1, strings.Count(u, "_"),
			"first_last entry %q must contain exactly one underscore", u)
		assert.False(t, strings.Contains(u, "."),
			"first_last entry %q must not contain dots (lastConcat strips them)", u)
	}

	// All entries must be non-empty and all-lowercase.
	for i, u := range result {
		assert.NotEmpty(t, u, "first_last: entry at index %d must not be empty", i)
		assert.Equal(t, strings.ToLower(u), u,
			"first_last: entry %q must be all lowercase", u)
	}

	// Deduplication: no duplicate entries.
	seen := make(map[string]bool, len(result))
	for _, u := range result {
		assert.False(t, seen[u],
			"first_last: duplicate entry found: %q", u)
		seen[u] = true
	}

	// Multi-part surname check: juan.dela.cruz → juan_delacruz (dots stripped).
	// The multi-part surname juan.dela.cruz should appear somewhere in the results
	// (if present in wordlist) as "juan_delacruz", not "juan_dela.cruz".
	for _, u := range result {
		assert.False(t, strings.Contains(u, "."),
			"first_last entry %q must not contain dots from multi-part surnames", u)
	}
}

// ---------------------------------------------------------------------------
// TestGenerateEmails_FirstUnderLast
// ---------------------------------------------------------------------------

// TestGenerateEmails_FirstUnderLast verifies that GenerateEmails with
// first_last format produces properly formatted email addresses.
func TestGenerateEmails_FirstUnderLast(t *testing.T) {
	t.Parallel()

	const domain = "kindermorgan.com"

	emails, err := GenerateEmails(FormatFirstUnderLast, domain)
	require.NoError(t, err)
	require.NotEmpty(t, emails)

	// Ranked head: john_smith@kindermorgan.com.
	if emails[0] != "john_smith@kindermorgan.com" {
		t.Logf("first_last email: expected first entry %q, got %q — reporting actual value",
			"john_smith@kindermorgan.com", emails[0])
	}
	assert.Equal(t, "john_smith@kindermorgan.com", emails[0],
		"first_last email: first entry must be john_smith@kindermorgan.com")

	// Every entry must end with @kindermorgan.com.
	suffix := "@" + domain
	for i, e := range emails {
		assert.True(t, strings.HasSuffix(e, suffix),
			"email at index %d (%q) must end with %q", i, e, suffix)
	}

	// Count must match the corresponding username generation.
	usernames, err := GenerateUsernames(FormatFirstUnderLast)
	require.NoError(t, err)
	assert.Equal(t, len(usernames), len(emails),
		"GenerateEmails must produce the same count as GenerateUsernames for first_last")
}

// ---------------------------------------------------------------------------
// 10T-535: GenerateCandidates
//
// GenerateUsernames/GenerateEmails throw away the (first, lastRaw) pair that
// formatUsername was derived from, forcing downstream consumers to
// reverse-derive a name from an ambiguous username (e.g. "jsmith" could be
// John, James, or Jane). GenerateCandidates must expose the name that was
// actually used, and GenerateUsernames/GenerateEmails must become thin
// wrappers over it so all existing call sites keep working unchanged.
// ---------------------------------------------------------------------------

// TestGenerateCandidates_UsernameParity verifies that GenerateCandidates and
// GenerateUsernames produce the exact same usernames, in the exact same
// order, for the same format. This pins the "thin wrapper" equivalence that
// the fix must preserve for all 8+ existing GenerateUsernames call sites.
func TestGenerateCandidates_UsernameParity(t *testing.T) {
	t.Parallel()

	formats := []string{FormatFirstDotLast, FormatFLast}

	for _, format := range formats {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			candidates, err := GenerateCandidates(format)
			require.NoError(t, err, "format %q must not error", format)

			usernames, err := GenerateUsernames(format)
			require.NoError(t, err, "format %q must not error", format)

			require.Equal(t, len(usernames), len(candidates),
				"format %q: GenerateCandidates and GenerateUsernames must produce the same count", format)

			for i := range usernames {
				assert.Equal(t, usernames[i], candidates[i].Username,
					"format %q: candidate %d Username must match GenerateUsernames[%d] (order preserved)",
					format, i, i)
			}
		})
	}
}

// TestGenerateCandidates_EmailParity verifies that, for a given domain,
// candidates[i].Email(domain) equals GenerateEmails(format, domain)[i] for
// every index, preserving both count and order.
func TestGenerateCandidates_EmailParity(t *testing.T) {
	t.Parallel()

	const domain = "example.com"
	formats := []string{FormatFirstDotLast, FormatFLast}

	for _, format := range formats {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			candidates, err := GenerateCandidates(format)
			require.NoError(t, err, "format %q must not error", format)

			emails, err := GenerateEmails(format, domain)
			require.NoError(t, err, "format %q must not error", format)

			require.Equal(t, len(emails), len(candidates),
				"format %q: GenerateCandidates and GenerateEmails must produce the same count", format)

			for i := range emails {
				assert.Equal(t, emails[i], candidates[i].Email(domain),
					"format %q: candidate %d Email(%q) must match GenerateEmails[%d]",
					format, i, domain, i)
			}
		})
	}
}

// TestGenerateCandidates_NamesPopulated verifies that every candidate carries
// a non-empty First and Last, for both a dotted format and an initial-based
// format.
func TestGenerateCandidates_NamesPopulated(t *testing.T) {
	t.Parallel()

	for _, format := range []string{FormatFirstDotLast, FormatFLast} {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			candidates, err := GenerateCandidates(format)
			require.NoError(t, err, "format %q must not error", format)
			require.NotEmpty(t, candidates, "format %q must produce at least one candidate", format)

			for i, c := range candidates {
				assert.NotEmpty(t, c.First, "format %q: candidate %d must have non-empty First", format, i)
				assert.NotEmpty(t, c.Last, "format %q: candidate %d must have non-empty Last", format, i)
			}
		})
	}
}

// TestGenerateCandidates_FullFirstNameSurvivesInitialFormat is THE POINT OF
// 10T-535: for an initial-based format (FormatFLast, e.g. "jsmith"), the
// candidate's First must be the full first name that was actually used to
// build the username, not a name reverse-derived from a single initial.
//
// FormatFLast usernames are always "<initial><lastname>" by construction
// (formatUsername returns first[:1]+lastConcat), so EVERY candidate's
// Username begins with a single-letter initial. If GenerateCandidates
// reduced First to that initial (or reverse-derived it from the username),
// First would never be longer than 1 character. This test would fail today
// under such an implementation because it requires at least one candidate
// with len(First) > 1, and it cross-checks every candidate's Username
// against the real formatUsername function to catch inconsistent
// First/Last/Username triples.
func TestGenerateCandidates_FullFirstNameSurvivesInitialFormat(t *testing.T) {
	t.Parallel()

	candidates, err := GenerateCandidates(FormatFLast)
	require.NoError(t, err)
	require.NotEmpty(t, candidates)

	var found bool
	for _, c := range candidates {
		require.NotEmpty(t, c.Username, "candidate must have a non-empty Username")
		require.NotEmpty(t, c.First, "candidate must have a non-empty First")

		// Cross-check against the real production formatting function (not a
		// reimplementation) to ensure First/Last actually produced Username.
		wantUsername := formatUsername(c.First, c.Last, FormatFLast)
		assert.Equal(t, wantUsername, c.Username,
			"candidate Username %q must be derivable from First %q / Last %q via formatUsername for FormatFLast",
			c.Username, c.First, c.Last)

		if len(c.First) > 1 {
			found = true
		}
	}

	assert.True(t, found,
		"expected at least one FormatFLast candidate with a full First name (len > 1) — "+
			"the point of 10T-535 is that the full first name survives even though the "+
			"username itself only exposes a single initial")
}

// TestGenerateCandidates_DottedLastNamesPreserved verifies that lastRaw
// components which themselves contain a dot (e.g. "al.mamun" from the source
// pair "abdullah.al.mamun") are preserved verbatim on Last, and that
// FormatFirstDotLast's Username reflects the full dotted Last name rather
// than being rebuilt by naively re-splitting the username on ".".
func TestGenerateCandidates_DottedLastNamesPreserved(t *testing.T) {
	t.Parallel()

	candidates, err := GenerateCandidates(FormatFirstDotLast)
	require.NoError(t, err)
	require.NotEmpty(t, candidates)

	var found bool
	for _, c := range candidates {
		if !strings.Contains(c.Last, ".") {
			continue
		}
		found = true

		// The username must be exactly First + "." + Last verbatim. A naive
		// implementation that re-splits the formatted username on the first
		// "." to recover First/Last would instead truncate Last to only the
		// portion after the first inner dot.
		assert.Equal(t, c.First+"."+c.Last, c.Username,
			"FormatFirstDotLast username must be First + \".\" + Last with the dotted Last preserved verbatim: got username %q, first %q, last %q",
			c.Username, c.First, c.Last)

		wantUsername := formatUsername(c.First, c.Last, FormatFirstDotLast)
		assert.Equal(t, wantUsername, c.Username,
			"candidate Username must match formatUsername(First, Last, FormatFirstDotLast)")
	}

	assert.True(t, found,
		"expected at least one FormatFirstDotLast candidate with a dotted Last "+
			"(e.g. \"al.mamun\" from source pair \"abdullah.al.mamun\")")
}

// TestGenerateCandidates_DedupMatchesUsernames verifies that GenerateCandidates
// dedups on Username with the same first-occurrence-wins semantics as
// GenerateUsernames: no two candidates share a Username, and the order of
// Usernames exactly matches GenerateUsernames.
func TestGenerateCandidates_DedupMatchesUsernames(t *testing.T) {
	t.Parallel()

	candidates, err := GenerateCandidates(FormatFLast)
	require.NoError(t, err)

	usernames, err := GenerateUsernames(FormatFLast)
	require.NoError(t, err)

	require.Equal(t, len(usernames), len(candidates))

	seen := make(map[string]bool, len(candidates))
	for i, c := range candidates {
		assert.False(t, seen[c.Username], "duplicate Username found in candidates: %q", c.Username)
		seen[c.Username] = true
		assert.Equal(t, usernames[i], c.Username,
			"candidate order must exactly match GenerateUsernames order (first occurrence wins)")
	}
}

// TestCandidate_Email verifies the Email method builds "username@domain".
func TestCandidate_Email(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		domain   string
		want     string
	}{
		{"simple", "jsmith", "example.com", "jsmith@example.com"},
		{"dotted username and multi-label domain", "john.smith", "corp.example.co.uk", "john.smith@corp.example.co.uk"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := Candidate{Username: tc.username}
			assert.Equal(t, tc.want, c.Email(tc.domain))
		})
	}
}

// TestGenerateCandidates_UnknownFormat verifies GenerateCandidates pins the
// exact current behavior of GenerateUsernames for a bogus format string:
// empty result, no error (formatUsername's default branch returns "" for
// every pair, and empty-string usernames are skipped). See
// TestGenerateUsernames_UnknownFormat above for the behavior being pinned.
func TestGenerateCandidates_UnknownFormat(t *testing.T) {
	t.Parallel()

	const bogusFormat = "totally-unknown-format"

	wantUsernames, err := GenerateUsernames(bogusFormat)
	require.NoError(t, err, "GenerateUsernames must not error on unknown format (current behavior)")
	assert.Empty(t, wantUsernames, "GenerateUsernames must return empty result on unknown format (current behavior)")

	candidates, err := GenerateCandidates(bogusFormat)
	require.NoError(t, err, "GenerateCandidates must not error on unknown format")
	assert.Empty(t, candidates, "GenerateCandidates must return an empty slice on unknown format")
	assert.Equal(t, len(wantUsernames), len(candidates),
		"GenerateCandidates must match GenerateUsernames's current unknown-format behavior exactly")
}

// TestGenerateCandidates_AllFormatsPopulated is a table-driven test verifying
// every supported format produces a non-empty result with fully populated
// First/Last/Username on every candidate.
func TestGenerateCandidates_AllFormatsPopulated(t *testing.T) {
	t.Parallel()

	for _, format := range ListFormats() {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			candidates, err := GenerateCandidates(format)
			require.NoError(t, err, "format %q must not error", format)
			require.NotEmpty(t, candidates, "format %q must produce at least one candidate", format)

			for i, c := range candidates {
				assert.NotEmpty(t, c.Username, "format %q: candidate %d must have non-empty Username", format, i)
				assert.NotEmpty(t, c.First, "format %q: candidate %d must have non-empty First", format, i)
				assert.NotEmpty(t, c.Last, "format %q: candidate %d must have non-empty Last", format, i)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10T-535: Candidate.Target
//
// Target carries a generated (or supplied) email together with the name it
// was built from, all the way through the enumeration framework to Result,
// so consumers never need to reverse-derive a name from an address (the
// "jsmith" could be John/James/Jane problem). Candidate.Target(domain) is the
// conversion point from generator output to framework input.
// ---------------------------------------------------------------------------

// TestCandidate_Target verifies that Candidate.Target(domain) produces an
// Email identical to Candidate.Email(domain), and carries First/Last through
// unchanged. Table-driven over several Candidate shapes.
func TestCandidate_Target(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		candidate Candidate
		domain    string
	}{
		{
			name:      "simple",
			candidate: Candidate{First: "john", Last: "smith", Username: "jsmith"},
			domain:    "example.com",
		},
		{
			name:      "dotted username and multi-label domain",
			candidate: Candidate{First: "john", Last: "smith", Username: "john.smith"},
			domain:    "corp.example.co.uk",
		},
		{
			name:      "dotted last name preserved",
			candidate: Candidate{First: "abdullah", Last: "al.mamun", Username: "abdullah.al.mamun"},
			domain:    "fox.com",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := tc.candidate.Target(tc.domain)

			assert.Equal(t, tc.candidate.Email(tc.domain), target.Email,
				"Target.Email must equal Candidate.Email(domain)")
			assert.Equal(t, tc.candidate.First, target.First,
				"Target.First must carry Candidate.First unchanged")
			assert.Equal(t, tc.candidate.Last, target.Last,
				"Target.Last must carry Candidate.Last unchanged")
		})
	}
}

// TestGenerateCandidates_TargetRoundTrip verifies the GenerateCandidates ->
// .Target(domain) round trip for a real format: every resulting Target has
// non-empty First, Last, and Email, and Email matches the corresponding
// GenerateEmails entry at the same index (order preserved).
func TestGenerateCandidates_TargetRoundTrip(t *testing.T) {
	t.Parallel()

	const domain = "example.com"

	candidates, err := GenerateCandidates(FormatFirstDotLast)
	require.NoError(t, err)
	require.NotEmpty(t, candidates)

	emails, err := GenerateEmails(FormatFirstDotLast, domain)
	require.NoError(t, err)
	require.Equal(t, len(candidates), len(emails),
		"GenerateCandidates and GenerateEmails must produce the same count")

	for i, c := range candidates {
		target := c.Target(domain)

		require.NotEmpty(t, target.Email, "candidate %d: Target.Email must not be empty", i)
		require.NotEmpty(t, target.First, "candidate %d: Target.First must not be empty", i)
		require.NotEmpty(t, target.Last, "candidate %d: Target.Last must not be empty", i)

		assert.Equal(t, emails[i], target.Email,
			"candidate %d: Target.Email must match GenerateEmails[%d] (order preserved)", i, i)
	}
}
