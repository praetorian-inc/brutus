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

// Package enum generates candidate usernames and emails for account
// enumeration.
//
// Username/email generation is driven by wordlists/likely-names.txt.gz, a
// frequency-ranked list of statistically likely "first.last" pairs (most
// likely first). That list is derived from the insidetrust/statistically-likely-usernames
// project (https://github.com/insidetrust/statistically-likely-usernames) and
// is bundled here per the maintainer's decision. See wordlists/SOURCES.md for
// full attribution. All username formats are derived from these ranked pairs,
// so output is bounded and ordered by likelihood.
package enum

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"strings"
)

//go:embed wordlists/*
var wordlistFS embed.FS

// Username format constants.
const (
	FormatFirstDotLast   = "first.last" // john.smith
	FormatFirstUnderLast = "first_last" // john_smith
	FormatFLast          = "flast"      // jsmith
	FormatFirstL         = "firstl"     // johns
	FormatFDotLast       = "f.last"     // j.smith
	FormatLastF          = "lastf"      // smithj
	FormatLastDotFirst   = "last.first" // smith.john
	FormatLastFirst      = "lastfirst"  // smithjohn
	FormatFirst          = "first"      // john
)

// ListFormats returns all available username format names.
func ListFormats() []string {
	return []string{
		FormatFirstDotLast,
		FormatFirstUnderLast,
		FormatFLast,
		FormatFirstL,
		FormatFDotLast,
		FormatLastF,
		FormatLastDotFirst,
		FormatLastFirst,
		FormatFirst,
	}
}

// GenerateUsernames derives usernames in the requested format from the
// frequency-ranked likely-names wordlist. Each source line is a "first.last"
// pair; the requested format is built from its parts. Results are lowercased,
// deduplicated preserving order (first occurrence wins, so output stays ranked
// by likelihood), and bounded by the wordlist size (<=248k).
func GenerateUsernames(format string) ([]string, error) {
	pairs, err := loadGzippedWordlist("wordlists/likely-names.txt.gz")
	if err != nil {
		return nil, fmt.Errorf("loading likely names: %w", err)
	}

	seen := make(map[string]bool, len(pairs))
	usernames := make([]string, 0, len(pairs))

	for _, pair := range pairs {
		pair = strings.ToLower(strings.TrimSpace(pair))

		// Split on the FIRST "." only. lastRaw may itself contain dots
		// (e.g. "al.mamun"), which FormatFirstDotLast preserves.
		first, lastRaw, ok := strings.Cut(pair, ".")
		if !ok || first == "" || lastRaw == "" {
			continue
		}

		u := formatUsername(first, lastRaw, format)
		if u == "" || seen[u] {
			continue
		}
		usernames = append(usernames, u)
		seen[u] = true
	}

	return usernames, nil
}

// GenerateEmails generates emails by appending @domain to usernames.
func GenerateEmails(format, domain string) ([]string, error) {
	usernames, err := GenerateUsernames(format)
	if err != nil {
		return nil, err
	}
	emails := make([]string, len(usernames))
	suffix := "@" + domain
	for i, u := range usernames {
		emails[i] = u + suffix
	}
	return emails, nil
}

// LoadServiceAccounts returns embedded service account names.
func LoadServiceAccounts() ([]string, error) {
	data, err := wordlistFS.ReadFile("wordlists/service-accounts.txt")
	if err != nil {
		return nil, fmt.Errorf("reading service accounts: %w", err)
	}
	var accounts []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			accounts = append(accounts, line)
		}
	}
	return accounts, scanner.Err()
}

// loadGzippedWordlist reads and decompresses a gzipped wordlist from the embedded FS.
func loadGzippedWordlist(path string) ([]string, error) {
	data, err := wordlistFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading embedded file %s: %w", path, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", path, err)
	}
	defer func() { _ = gz.Close() }()

	var lines []string
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// formatUsername derives a username in the given format from a first name and
// the raw last-name component of a "first.last" pair. lastRaw may contain dots
// (multi-part surnames); lastConcat strips them for concatenated/initial
// formats, while FormatFirstDotLast emits the original pair to preserve the
// multi-part name. Returns "" when the format needs an initial that isn't
// available.
func formatUsername(first, lastRaw, format string) string {
	lastConcat := strings.ReplaceAll(lastRaw, ".", "")

	switch format {
	case FormatFirstDotLast:
		return first + "." + lastRaw
	case FormatFirstUnderLast:
		if lastConcat == "" {
			return ""
		}
		return first + "_" + lastConcat
	case FormatFLast:
		if lastConcat == "" {
			return ""
		}
		return first[:1] + lastConcat
	case FormatFirstL:
		if lastConcat == "" {
			return ""
		}
		return first + lastConcat[:1]
	case FormatFDotLast:
		if lastConcat == "" {
			return ""
		}
		return first[:1] + "." + lastConcat
	case FormatLastF:
		return lastConcat + first[:1]
	case FormatLastDotFirst:
		return lastConcat + "." + first
	case FormatLastFirst:
		return lastConcat + first
	case FormatFirst:
		return first
	default:
		return ""
	}
}
