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

// Package creds provides credential-testing domain logic for the "brutus creds"
// subcommand: protocol filtering and SNMP community string configuration.
package creds

import (
	"fmt"

	"github.com/praetorian-inc/brutus/internal/plugins/snmp"
)

// httpProtocols lists protocols handled by the "web" subcommand (not "creds").
// Keep in sync with the identical map in pkg/brutus/web/web.go.
var httpProtocols = map[string]bool{
	"http":    true,
	"https":   true,
	"browser": true,
}

// IsCredsProtocol returns true for non-HTTP protocols handled by the "creds" subcommand.
func IsCredsProtocol(protocol string) bool {
	return !httpProtocols[protocol]
}

// ConfigureSNMP validates the tier string and returns the corresponding community
// strings. The caller is responsible for assigning them to config.Passwords.
func ConfigureSNMP(tier string) ([]string, error) {
	if !snmp.ValidateTier(tier) {
		return nil, fmt.Errorf("invalid --snmp-tier: %s (use: default, extended, full)", tier)
	}
	return snmp.GetCommunityStrings(snmp.Tier(tier)), nil
}
