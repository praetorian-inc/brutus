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

// ConfigureSNMP validates the mode string and returns the corresponding community
// strings. It accepts both the new mode names (cautious, default, aggressive) and
// the legacy SNMP tier names (default, extended, full).
// The caller is responsible for assigning the result to config.Passwords.
func ConfigureSNMP(mode string) ([]string, error) {
	snmpTier := mapModeToSNMPTier(mode)
	if !snmpplugin.ValidateTier(snmpTier) {
		return nil, fmt.Errorf("invalid --mode: %s (use: cautious, default, aggressive, extended, full)", mode)
	}
	return snmpplugin.GetCommunityStrings(snmpplugin.Tier(snmpTier)), nil
}

// mapModeToSNMPTier converts the global mode names to SNMP-specific tier names.
// The SNMP plugin has its own tier constants (default, extended, full) that
// predate the global mode system; this mapping bridges the two.
func mapModeToSNMPTier(mode string) string {
	switch mode {
	case "cautious":
		return "default" // SNMP's smallest tier (~25 strings)
	case "aggressive":
		return "full" // SNMP's largest tier (~200+ strings)
	default:
		// "default" passes through; legacy "extended" and "full" also pass through
		// since the SNMP plugin's ValidateTier accepts them directly.
		return mode
	}
}
