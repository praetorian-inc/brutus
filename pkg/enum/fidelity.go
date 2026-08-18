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

import "unicode/utf8"

// FieldFidelity describes how much of one part of a person's name a generated
// username actually proves.
//
// GenerateCandidates carries the full "first.last" pair each username was built
// from, which is what a consumer needs in order to avoid reverse-deriving a name
// from the local part. But carrying the pair does not make the pair a fact: a
// lossy format discards part of it, and dedup on the username silently drops
// every colliding pair, so the surviving First/Last is merely the
// highest-ranked expansion. "jsmith" proves that the given name starts with J
// and nothing more, whether our wordlist holds one candidate for it or 264.
//
// The decisive point is that ambiguity within the wordlist is the wrong test.
// The wordlist is a frequency-ranked sample (248k pairs), not the universe of
// names, so a username with exactly one expansion in it still has no proven
// given name -- the real owner may hold a name the list does not contain.
// Uniqueness in the sample cannot be evidence. What the address does prove is
// determined entirely by the format, which is why fidelity is a function of the
// format string and needs no data source at all.
type FieldFidelity int

const (
	// FieldAbsent means the format does not encode this part of the name in any
	// form. Whatever value the Candidate carries for it came from the wordlist
	// pair, not from the address, and must not be presented as the person's
	// name.
	FieldAbsent FieldFidelity = iota

	// FieldInitial means only the part's first letter is recoverable. The
	// initial itself is definitionally correct -- formatUsername built the
	// username from that letter -- but the rest is unknowable.
	FieldInitial

	// FieldExact means the format encodes the part in full.
	FieldExact
)

// String renders a FieldFidelity for logs and test failure messages.
func (f FieldFidelity) String() string {
	switch f {
	case FieldAbsent:
		return "absent"
	case FieldInitial:
		return "initial"
	case FieldExact:
		return "exact"
	default:
		return "unknown"
	}
}

// FormatFidelity reports how much of the given name and surname the usernames
// produced by format actually prove.
//
// This mirrors formatUsername case for case, and the two must be changed
// together: adding a format there without answering the fidelity question here
// makes the new format report FieldAbsent for the given name, which
// TestFormatFidelity_EveryFormatMapped fails on deliberately.
//
// An unrecognized format reports FieldAbsent for both parts, matching
// GenerateCandidates, which yields no candidates at all for a format
// formatUsername does not know.
func FormatFidelity(format string) (first, last FieldFidelity) {
	switch format {
	// Both parts present and separator-delimited, so the split is unambiguous.
	case FormatFirstDotLast, FormatLastDotFirst, FormatFirstUnderLast:
		return FieldExact, FieldExact

	// Both parts present in full but run together, so the boundary is not
	// recoverable from the string alone ("limandy" is Andy Lim or Mandy Li).
	// Measured against the shipped wordlist this affects 6 of 248,093 generated
	// usernames (0.00%), which is too rare to justify a distinct fidelity state
	// and far rarer than initial truncation, where a majority of usernames are
	// affected.
	case FormatLastFirst:
		return FieldExact, FieldExact

	// The given name is reduced to its initial; the surname survives in full.
	case FormatFLast, FormatFDotLast, FormatLastF:
		return FieldInitial, FieldExact

	// The inverse: the given name survives in full, the surname is reduced to
	// its initial.
	case FormatFirstL:
		return FieldExact, FieldInitial

	// "john@example.com" carries no surname whatsoever. The Candidate still
	// holds one, because every "john.*" pair collapses to the same username and
	// the highest-ranked pair's surname survives dedup, but that surname has no
	// basis in the address at all -- it is the one case where the carried value
	// is not even a truncation of something the username contains.
	case FormatFirst:
		return FieldExact, FieldAbsent

	default:
		return FieldAbsent, FieldAbsent
	}
}

// KnownName reduces a generated name to only the parts the address demonstrates,
// given the format it was generated in.
//
// Callers labeling a confirmed hit with a person's name should use this rather
// than a Candidate's or Result's raw First/Last, so that a lossy format yields
// an initial instead of a specific name nobody can justify:
//
//	KnownName(FormatFLast, "John", "Smith")       // "J", "Smith"
//	KnownName(FormatFirstL, "John", "Smith")      // "John", "S"
//	KnownName(FormatFirst, "John", "Smith")       // "John", ""
//	KnownName(FormatFirstDotLast, "John", "Smith") // "John", "Smith"
//
// It exists as a helper, rather than leaving each consumer to switch on
// FormatFidelity itself, so that the reduction is written and tested once. Two
// consumers implementing it independently would be two chances to reintroduce
// the guess.
//
// The returned strings are projections of the inputs: no title-casing, no
// trimming, no normalization. Presentation is the caller's concern, and
// silently transforming here would make the output disagree with the Candidate
// fields it derives from.
func KnownName(format, first, last string) (knownFirst, knownLast string) {
	firstFidelity, lastFidelity := FormatFidelity(format)
	return reduceToFidelity(first, firstFidelity), reduceToFidelity(last, lastFidelity)
}

// reduceToFidelity projects a single name part down to its proven form.
//
// The initial is taken by rune rather than by byte. formatUsername slices bytes
// (first[:1]), which is equivalent for every pair in the shipped wordlist since
// all 248,231 are ASCII, but KnownName is exported and may be handed a name from
// elsewhere, where byte-slicing a multi-byte rune would emit an invalid UTF-8
// fragment.
func reduceToFidelity(value string, fidelity FieldFidelity) string {
	switch fidelity {
	case FieldExact:
		return value
	case FieldInitial:
		// DecodeRuneInString returns (RuneError, 0) for the empty string and
		// (RuneError, 1) for an undecodable byte, so this single check covers
		// both: no initial is better than a broken one, and an explicit
		// empty-string guard above would be unreachable.
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size <= 1 {
			return ""
		}
		return value[:size]
	default:
		return ""
	}
}
