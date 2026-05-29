package brutus

import (
	"embed"
	"strings"
)

//go:embed wordlists/*.txt
var wordlistsFS embed.FS

// Tier marker comments recognized in wordlist files.
const (
	markerCautious   = "# --- cautious ---"
	markerExhaustive = "# --- exhaustive ---"
)

// maxCautiousFallback is the maximum number of credentials returned for
// ModeCautious when a wordlist file has no tier markers.
const maxCautiousFallback = 5

// DefaultCredentials returns the default username:password pairs for a protocol
// by parsing the embedded wordlist file. Returns nil if no wordlist exists for
// the protocol. Each entry is a Credential with Username and Password set.
//
// This is equivalent to DefaultCredentialsForMode(protocol, ModeDefault).
func DefaultCredentials(protocol string) []Credential {
	return DefaultCredentialsForMode(protocol, ModeDefault)
}

// DefaultCredentialsForMode returns default credentials for a protocol filtered
// by the specified aggressiveness mode.
//
// Wordlist files use optional section markers to define tier boundaries:
//
//	root:root           ← cautious tier (lines before first marker)
//	admin:admin
//	# --- cautious ---
//	root:password       ← default tier (added for default + exhaustive)
//	root:toor
//	# --- exhaustive ---
//	vendor:vendor123    ← exhaustive tier (added only for exhaustive)
//
// Files without markers: cautious returns the first 5 entries, default and
// exhaustive return all entries.
func DefaultCredentialsForMode(protocol string, mode Mode) []Credential {
	data, err := wordlistsFS.ReadFile("wordlists/" + protocol + "_defaults.txt")
	if err != nil {
		return nil
	}
	return parseWordlistTiered(string(data), mode)
}

// parseWordlistTiered parses a wordlist with optional tier markers.
func parseWordlistTiered(content string, mode Mode) []Credential {
	lines := strings.Split(content, "\n")

	// Partition lines into three sections based on markers.
	var cautiousLines, defaultLines, exhaustiveLines []string
	section := "cautious" // lines before any marker are highest-confidence
	hasMarkers := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == markerCautious {
			hasMarkers = true
			section = "default"
			continue
		}
		if trimmed == markerExhaustive {
			hasMarkers = true
			section = "exhaustive"
			continue
		}

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		switch section {
		case "cautious":
			cautiousLines = append(cautiousLines, trimmed)
		case "default":
			defaultLines = append(defaultLines, trimmed)
		case "exhaustive":
			exhaustiveLines = append(exhaustiveLines, trimmed)
		}
	}

	// When the file has no markers, all non-comment lines end up in
	// cautiousLines. For ModeDefault and ModeExhaustive this is fine (they
	// get everything). For ModeCautious we cap at maxCautiousFallback.
	if !hasMarkers && mode == ModeCautious && len(cautiousLines) > maxCautiousFallback {
		cautiousLines = cautiousLines[:maxCautiousFallback]
	}

	// Build the selected line set based on mode.
	var selected []string
	switch mode {
	case ModeCautious:
		selected = cautiousLines
	case ModeExhaustive:
		selected = make([]string, 0, len(cautiousLines)+len(defaultLines)+len(exhaustiveLines))
		selected = append(selected, cautiousLines...)
		selected = append(selected, defaultLines...)
		selected = append(selected, exhaustiveLines...)
	default: // ModeDefault
		selected = make([]string, 0, len(cautiousLines)+len(defaultLines))
		selected = append(selected, cautiousLines...)
		selected = append(selected, defaultLines...)
	}

	return parseLines(selected)
}

// parseLines converts raw credential lines into Credential pairs.
// Format is username:password per line. A line without a colon is treated as
// password-only (e.g., SNMP community strings).
func parseLines(lines []string) []Credential {
	var creds []Credential
	for _, line := range lines {
		username, password, found := strings.Cut(line, ":")
		if !found {
			creds = append(creds, Credential{Password: line})
		} else {
			creds = append(creds, Credential{Username: username, Password: password})
		}
	}
	return creds
}

// parseWordlist parses a wordlist file into Credential pairs.
// Lines starting with # are comments. Format is username:password per line.
// A line with just "community_string" (no colon) is treated as password-only.
//
// Deprecated: Use parseWordlistTiered for mode-aware loading.
func parseWordlist(content string) []Credential {
	var creds []Credential
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		username, password, found := strings.Cut(line, ":")
		if !found {
			creds = append(creds, Credential{Password: line})
		} else {
			creds = append(creds, Credential{Username: username, Password: password})
		}
	}
	return creds
}
