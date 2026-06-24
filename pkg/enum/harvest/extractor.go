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

// pkg/enum/harvest/extractor.go
package harvest

import (
	"regexp"
	"strings"
)

// emailRe is a pragmatic (not full RFC 5322) email matcher. It is compiled once
// at package init. It uses Go's regexp (RE2): linear-time, no backtracking, so
// it is ReDoS-safe even on attacker-influenced SERP/cert HTML (security P0-4).
// The domain is NOT interpolated into this pattern; domain anchoring is enforced
// afterward by host comparison, so no regex-metacharacter injection is possible.
var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// roleAccounts are role/noise localparts dropped when rejectRoles is true. They
// inflate noise from SERP snippets without identifying a person. Hardcoded set
// (KISS — not configurable).
var roleAccounts = map[string]struct{}{
	"noreply":       {},
	"no-reply":      {},
	"donotreply":    {},
	"postmaster":    {},
	"abuse":         {},
	"mailer-daemon": {},
}

// ExtractEmails finds, normalizes, and domain-anchors emails in text.
// It lowercases, strips a leading "mailto:" and trailing punctuation, rejects
// role/noise accounts when rejectRoles is true, keeps only addresses whose host
// is domain or a subdomain of domain, and dedupes. Returns nil when none match.
//
// The input is expected to already be size-capped by the caller (security P0-3);
// combined with RE2's linear-time guarantee this bounds worst-case CPU.
func ExtractEmails(text, domain string, rejectRoles bool) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	matches := emailRe.FindAllString(text, -1)
	if matches == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string
	for _, raw := range matches {
		email := normalize(raw)
		if email == "" {
			continue
		}

		at := strings.LastIndex(email, "@")
		if at <= 0 || at == len(email)-1 {
			continue
		}
		local := email[:at]
		host := email[at+1:]

		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		if rejectRoles && isRole(local) {
			continue
		}
		if _, dup := seen[email]; dup {
			continue
		}

		seen[email] = struct{}{}
		out = append(out, email)
	}

	return out
}

// normalize lowercases an email candidate and trims a leading "mailto:" prefix
// plus trailing punctuation/word-boundary junk left over from surrounding text.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "mailto:")
	s = strings.Trim(s, ".,;:!?)\"'<>(")
	return s
}

// isRole reports whether localpart is a hardcoded role/noise account.
func isRole(localpart string) bool {
	_, ok := roleAccounts[localpart]
	return ok
}
