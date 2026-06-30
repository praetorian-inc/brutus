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
	"github.com/spf13/cobra"

	snmpPkg "github.com/praetorian-inc/brutus/pkg/brutus/snmp"
)

var snmpCmd = &cobra.Command{
	Use:     "snmp",
	Aliases: []string{"community"},
	Short:   "Test SNMP community strings against targets",
	Long: `Audit SNMP v1/v2c community strings against network devices, routers,
switches, and other SNMP-enabled infrastructure.

Community strings are selected by mode:
  cautious    ~25 common strings (public, private, community, etc.)
  default     ~25 strings (same as cautious)
  aggressive  ~200+ strings (comprehensive: vendor-specific, SCADA, IP cameras, storage, etc.)

Custom community strings can also be provided via -c or -C.`,
	Example: `  # Test with default community strings
  brutus snmp --target 192.168.1.1:161

  # Aggressive mode for comprehensive testing (~200+ strings)
  brutus snmp --target 10.0.0.1:161 --mode aggressive

  # Custom community strings
  brutus snmp --target 192.168.1.1:161 -c "mycommunity,secretstring"

  # Pipeline mode
  naabu -host 10.0.0.0/24 -p 161 -silent | nerva --json | brutus snmp

  # Targets file
  brutus snmp --targets-file snmp-hosts.txt --mode aggressive

  # Import targets from nmap XML scan (only SNMP services tested)
  brutus snmp --nmap-file scan.xml --mode aggressive`,
	RunE: runSNMP,
}

func init() {
	registerSNMPFlags(snmpCmd)
}

func runSNMP(cmd *cobra.Command, args []string) error {
	base, err := buildBaseConfig(cmd)
	if err != nil {
		return err
	}

	// Load custom community strings from -c/-C
	communityFlagSet := isFlagChanged(cmd, "community")
	passwords, err := loadPasswords(flagCommunityStrings, flagCommunityFile, communityFlagSet)
	if err != nil {
		return err
	}

	// If no custom community strings, load from mode.
	// Use flagMode directly since SNMP has its own legacy tier names
	// (extended, full) that NormalizeMode would map to "default".
	if len(passwords) == 0 {
		passwords, err = snmpPkg.ConfigureSNMP(flagMode)
		if err != nil {
			return err
		}
	}
	base.passwords = passwords

	// SNMP mode: force protocol, disable irrelevant features
	base.protocolOverride = "snmp"
	base.protocolFilter = snmpPkg.IsSNMPProtocol
	base.aiMode = false
	base.useBadkeys = false
	base.badkeysOnly = false

	return runSubcommand(cmd, &runConfig{baseConfigOptions: base})
}
