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

Community strings are selected by tier:
  default   ~20 common strings (public, private, community, etc.)
  extended  ~50 strings (adds vendor-specific: Cisco, HP, Juniper, etc.)
  full      ~120 strings (comprehensive: SCADA, IP cameras, storage, etc.)

Custom community strings can also be provided via -p or -P.`,
	Example: `  # Test with default community strings
  brutus snmp --target 192.168.1.1:161

  # Use extended tier for more coverage
  brutus snmp --target 192.168.1.1:161 --tier extended

  # Full tier for comprehensive testing
  brutus snmp --target 10.0.0.1:161 --tier full

  # Custom community strings
  brutus snmp --target 192.168.1.1:161 -p "mycommunity,secretstring"

  # Pipeline mode
  naabu -host 10.0.0.0/24 -p 161 -silent | nerva --json | brutus snmp

  # Targets file
  brutus snmp --targets-file snmp-hosts.txt --tier extended`,
	RunE: runSNMP,
}

func init() {
	registerSNMPFlags(snmpCmd)
}

func runSNMP(cmd *cobra.Command, args []string) error {
	baseConfig, err := buildConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	// SNMP mode: force protocol, disable irrelevant features
	baseConfig.protocolOverride = "snmp"
	baseConfig.protocolFilter = snmpPkg.IsSNMPProtocol
	baseConfig.aiMode = false
	baseConfig.stickyKeys = false
	baseConfig.useBadkeys = false
	baseConfig.badkeysOnly = false

	return runSubcommand(cmd, baseConfig)
}
