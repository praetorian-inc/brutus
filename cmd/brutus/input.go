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
	"strings"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func loadPasswords(inline, file string, inlineFlagSet bool) ([]string, error) {
	var passwords []string

	// Load from inline flag
	if inlineFlagSet {
		passwords = append(passwords, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		filePasswords, err := brutus.LoadPasswordsFromFile(file)
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
		fileUsernames, err := brutus.LoadUsernamesFromFile(file)
		if err != nil {
			return nil, err
		}
		usernames = append(usernames, fileUsernames...)
	}

	return usernames, nil
}

func loadKey(keyFile string) ([][]byte, error) {
	return brutus.LoadKeyFile(keyFile)
}
