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

// Package bruteutil provides convenience functions that bridge pkg/badkeys
// and pkg/brutus. It lives in a sub-package to avoid a circular dependency
// between the two.
package bruteutil

import (
	"time"

	"github.com/praetorian-inc/brutus/pkg/badkeys"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// NewSSHConfig creates a brutus.Config pre-populated with all known bad SSH keys
// and their associated usernames for comprehensive SSH key brute forcing.
//
// The target should be in host:port format (e.g., "10.0.0.50:22").
//
// Example:
//
//	config := bruteutil.NewSSHConfig("10.0.0.50:22")
//	results, err := brutus.Brute(config)
func NewSSHConfig(target string) *brutus.Config {
	creds := badkeys.GetExpandedSSHCredentials()

	usernameSet := make(map[string]bool)
	var keys [][]byte

	keySet := make(map[string]bool)
	for _, cred := range creds {
		usernameSet[cred.Username] = true
		keyStr := string(cred.Key)
		if !keySet[keyStr] {
			keySet[keyStr] = true
			keys = append(keys, cred.Key)
		}
	}

	var usernames []string
	for u := range usernameSet {
		usernames = append(usernames, u)
	}

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     usernames,
		Keys:          keys,
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// NewSSHConfigForProduct creates a brutus.Config for a specific product's keys.
//
// Example:
//
//	config := bruteutil.NewSSHConfigForProduct("10.0.0.50:22", "vagrant")
//	results, err := brutus.Brute(config)
func NewSSHConfigForProduct(target, product string) *brutus.Config {
	creds := badkeys.GetCredentialsByProduct(product)
	if len(creds) == 0 {
		return NewSSHConfig(target)
	}

	usernameSet := make(map[string]bool)
	var keys [][]byte

	for _, cred := range creds {
		usernameSet[cred.Username] = true
		keys = append(keys, cred.Key)
	}

	var usernames []string
	for u := range usernameSet {
		usernames = append(usernames, u)
	}

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     usernames,
		Keys:          keys,
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// NewSSHConfigWithPasswords creates a brutus.Config that combines bad keys
// with a list of passwords for comprehensive SSH testing.
//
// Example:
//
//	config := bruteutil.NewSSHConfigWithPasswords(
//	    "10.0.0.50:22",
//	    []string{"root", "admin", "vagrant"},
//	    []string{"password", "admin", "root123"},
//	)
//	results, err := brutus.Brute(config)
func NewSSHConfigWithPasswords(target string, usernames, passwords []string) *brutus.Config {
	usernameSet := make(map[string]bool)
	for _, u := range usernames {
		usernameSet[u] = true
	}
	for _, u := range badkeys.GetUsernames() {
		usernameSet[u] = true
	}

	var allUsernames []string
	for u := range usernameSet {
		allUsernames = append(allUsernames, u)
	}

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     allUsernames,
		Passwords:     passwords,
		Keys:          badkeys.GetKeys(),
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// SSHKeyCredential represents a username:key pair for direct testing.
type SSHKeyCredential struct {
	Username string
	Key      []byte
}

// GetSSHKeyCredentials returns all username:key pairs for direct testing.
func GetSSHKeyCredentials() []SSHKeyCredential {
	expanded := badkeys.GetExpandedSSHCredentials()
	creds := make([]SSHKeyCredential, len(expanded))
	for i, e := range expanded {
		creds[i] = SSHKeyCredential{Username: e.Username, Key: e.Key}
	}
	return creds
}

// BruteSSH performs SSH key brute forcing using all known bad keys.
func BruteSSH(target string) ([]brutus.Result, error) {
	return brutus.Brute(NewSSHConfig(target))
}

// BruteSSHProduct performs SSH key brute forcing for a specific product.
func BruteSSHProduct(target, product string) ([]brutus.Result, error) {
	return brutus.Brute(NewSSHConfigForProduct(target, product))
}
