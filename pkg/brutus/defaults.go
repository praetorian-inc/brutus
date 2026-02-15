package brutus

import (
	"embed"
	"strings"
)

//go:embed wordlists/*.txt
var wordlistsFS embed.FS

// DefaultCredentials returns the default username:password pairs for a protocol
// by parsing the embedded wordlist file. Returns nil if no wordlist exists for
// the protocol. Each entry is a Credential with Username and Password set.
func DefaultCredentials(protocol string) []Credential {
	data, err := wordlistsFS.ReadFile("wordlists/" + protocol + "_defaults.txt")
	if err != nil {
		return nil
	}
	return parseWordlist(string(data))
}

// parseWordlist parses a wordlist file into Credential pairs.
// Lines starting with # are comments. Format is username:password per line.
// A line with just "community_string" (no colon) is treated as password-only.
func parseWordlist(content string) []Credential {
	var creds []Credential
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		username, password, _ := strings.Cut(line, ":")
		creds = append(creds, Credential{Username: username, Password: password})
	}
	return creds
}
