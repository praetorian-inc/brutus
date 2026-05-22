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
	FormatFirstDotLast = "first.last" // john.smith
	FormatFLast        = "flast"      // jsmith
	FormatFirstL       = "firstl"     // johns
	FormatFDotLast     = "f.last"     // j.smith
	FormatLastF        = "lastf"      // smithj
	FormatLastDotFirst = "last.first" // smith.john
	FormatLastFirst    = "lastfirst"  // smithjohn
	FormatFirst        = "first"      // john
)

// ListFormats returns all available username format names.
func ListFormats() []string {
	return []string{
		FormatFirstDotLast,
		FormatFLast,
		FormatFirstL,
		FormatFDotLast,
		FormatLastF,
		FormatLastDotFirst,
		FormatLastFirst,
		FormatFirst,
	}
}

// GenerateUsernames loads embedded first/last name lists and generates
// usernames in the specified format. Returns deduplicated, lowercased usernames.
func GenerateUsernames(format string) ([]string, error) {
	firstNames, err := loadGzippedWordlist("wordlists/firstnames.txt.gz")
	if err != nil {
		return nil, fmt.Errorf("loading first names: %w", err)
	}

	// first-name-only format
	if format == FormatFirst {
		seen := make(map[string]bool, len(firstNames))
		var out []string
		for _, f := range firstNames {
			f = strings.ToLower(strings.TrimSpace(f))
			if f != "" && !seen[f] {
				out = append(out, f)
				seen[f] = true
			}
		}
		return out, nil
	}

	lastNames, err := loadGzippedWordlist("wordlists/lastnames.txt.gz")
	if err != nil {
		return nil, fmt.Errorf("loading last names: %w", err)
	}

	seen := make(map[string]bool, len(firstNames)*len(lastNames))
	var usernames []string

	for _, first := range firstNames {
		first = strings.ToLower(strings.TrimSpace(first))
		if first == "" {
			continue
		}
		for _, last := range lastNames {
			last = strings.ToLower(strings.TrimSpace(last))
			if last == "" {
				continue
			}
			u := formatUsername(first, last, format)
			if u != "" && !seen[u] {
				usernames = append(usernames, u)
				seen[u] = true
			}
		}
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
	defer gz.Close()

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

// formatUsername applies a format template to a first+last name pair.
func formatUsername(first, last, format string) string {
	switch format {
	case FormatFirstDotLast:
		return first + "." + last
	case FormatFLast:
		return first[:1] + last
	case FormatFirstL:
		return first + last[:1]
	case FormatFDotLast:
		return first[:1] + "." + last
	case FormatLastF:
		return last + first[:1]
	case FormatLastDotFirst:
		return last + "." + first
	case FormatLastFirst:
		return last + first
	case FormatFirst:
		return first
	default:
		return ""
	}
}
