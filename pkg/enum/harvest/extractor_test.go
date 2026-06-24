// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package harvest

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExtractEmails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		text        string
		domain      string
		rejectRoles bool
		want        []string
	}{
		{"plain match", "contact jane.doe@acme.com today", "acme.com", false, []string{"jane.doe@acme.com"}},
		{"lowercases", "JANE.DOE@ACME.COM", "acme.com", false, []string{"jane.doe@acme.com"}},
		{"strips mailto prefix", "mailto:bob@acme.com", "acme.com", false, []string{"bob@acme.com"}},
		{"strips trailing punctuation", "see al@acme.com.", "acme.com", false, []string{"al@acme.com"}},
		{"drops other domains", "x@other.com and y@acme.com", "acme.com", false, []string{"y@acme.com"}},
		{"keeps subdomain", "z@mail.acme.com", "acme.com", false, []string{"z@mail.acme.com"}},
		{"dedupes", "a@acme.com a@acme.com A@ACME.COM", "acme.com", false, []string{"a@acme.com"}},
		{"rejects role accounts when asked", "noreply@acme.com real@acme.com", "acme.com", true, []string{"real@acme.com"}},
		{"keeps role accounts when not asked", "abuse@acme.com", "acme.com", false, []string{"abuse@acme.com"}},
		{"no matches", "nothing here", "acme.com", false, nil},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractEmails(tc.text, tc.domain, tc.rejectRoles)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			assert.Equal(t, want, got)
		})
	}
}

// TestExtractEmailsReDoSSafety proves that the RE2-backed extractor completes
// in well under 1 second even on a pathological input made of tens of KB of
// '@' and 'a' repetitions. This regression guards the security P0-4 guarantee
// (linear-time, no-backtracking regex engine).
func TestExtractEmailsReDoSSafety(t *testing.T) {
	t.Parallel()
	// Build a ~50 KB string of alternating '@' and 'a' — the classic
	// catastrophic-backtracking payload for naive email regexes.
	var sb strings.Builder
	for i := 0; i < 50_000; i++ {
		if i%2 == 0 {
			sb.WriteByte('@')
		} else {
			sb.WriteByte('a')
		}
	}
	input := sb.String()

	start := time.Now()
	got := ExtractEmails(input, "acme.com", false)
	elapsed := time.Since(start)

	assert.Nil(t, got, "pathological input must yield no emails")
	assert.Less(t, elapsed, time.Second, "ExtractEmails must complete in < 1s on pathological input (RE2 linear-time guarantee)")
}
