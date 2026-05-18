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

package main

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
)

func loadPasswords(inline, file string, inlineFlagSet bool) ([]string, error) {
	var passwords []string

	// Load from inline flag
	if inlineFlagSet {
		passwords = append(passwords, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		filePasswords, err := brutusinput.LoadPasswordsFromFile(file)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, filePasswords...)
	}

	return passwords, nil
}

func loadUsernames(inline, file string, inlineFlagSet bool) ([]string, error) {
	var usernames []string

	// Load from inline flag
	if inlineFlagSet {
		usernames = append(usernames, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		fileUsernames, err := brutusinput.LoadUsernamesFromFile(file)
		if err != nil {
			return nil, err
		}
		usernames = append(usernames, fileUsernames...)
	}

	return usernames, nil
}

func loadKey(keyFile string) ([][]byte, error) {
	return brutusinput.LoadKeyFile(keyFile)
}

// loadCredentials parses pre-paired user:pass credentials from inline and file sources.
func loadCredentials(inline, file string) ([]brutus.Credential, error) {
	var creds []brutus.Credential

	if inline != "" {
		parsed, err := parseCredentialPairs(inline)
		if err != nil {
			return nil, err
		}
		creds = append(creds, parsed...)
	}

	if file != "" {
		// Reuse username loader for line parsing (skips comments and blank lines)
		lines, err := brutusinput.LoadUsernamesFromFile(file)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			u, p, ok := strings.Cut(line, ":")
			if !ok {
				return nil, fmt.Errorf("invalid credential in %s: %q (expected user:pass)", file, line)
			}
			creds = append(creds, brutus.Credential{Username: u, Password: p})
		}
	}

	return creds, nil
}

// parseCredentialPairs splits a comma-separated string of user:pass pairs.
func parseCredentialPairs(s string) ([]brutus.Credential, error) {
	var creds []brutus.Credential
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		u, p, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("invalid credential pair: %q (expected user:pass)", pair)
		}
		creds = append(creds, brutus.Credential{Username: u, Password: p})
	}
	return creds, nil
}
