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

// Package snmp provides SNMP domain logic for the "brutus snmp" subcommand:
// protocol filtering and community string tier configuration.
package snmp

import (
	"fmt"

	snmpplugin "github.com/praetorian-inc/brutus/internal/plugins/snmp"
)

// IsSNMPProtocol returns true if the protocol is SNMP.
func IsSNMPProtocol(protocol string) bool {
	return protocol == "snmp"
}

// ConfigureSNMP validates the tier string and returns the corresponding community
// strings. The caller is responsible for assigning them to config.Passwords.
func ConfigureSNMP(tier string) ([]string, error) {
	if !snmpplugin.ValidateTier(tier) {
		return nil, fmt.Errorf("invalid --tier: %s (use: default, extended, full)", tier)
	}
	return snmpplugin.GetCommunityStrings(snmpplugin.Tier(tier)), nil
}
