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
)

var credsCmd = &cobra.Command{
	Use:     "creds",
	Aliases: []string{"services", "defaults", "credentials"},
	Short:   "Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)",
	Long: `Audit default and weak credentials across network services, databases,
and enterprise protocols such as SSH, RDP, MySQL, PostgreSQL, SMB, LDAP,
Redis, SNMP, and more.

If --protocol http is explicitly set, only HTTP Basic Auth with default
credentials will be tested. For full web panel auditing including form-based
login and AI-powered detection, use "brutus web" instead.

In pipeline/fingerprint mode, HTTP-like services are automatically skipped.`,
	Example: `  # Single target
  brutus creds --target 192.168.1.10:22 --protocol ssh -p "password,Password1"

  # Fingerprint targets and test default credentials
  brutus creds --fingerprint targets.txt -u admin -P passwords.txt

  # Pipeline mode (HTTP services are skipped)
  naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt

  # SNMP community string testing
  brutus creds --target 192.168.1.1:161 --protocol snmp --snmp-tier full

  # SSH with bad keys only
  brutus creds --target 192.168.1.10:22 --protocol ssh --badkeys-only`,
	RunE: runCreds,
}

func init() {
	registerCredsFlags(credsCmd)
}

func runCreds(cmd *cobra.Command, args []string) error {
	baseConfig, err := buildConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	// Creds mode never uses AI browser automation or sticky keys
	baseConfig.aiMode = false
	baseConfig.stickyKeys = false

	// In pipeline/fingerprint mode, skip HTTP-like protocols.
	// If --protocol is explicitly set to http, we still allow it (basic auth only)
	// but don't install a filter since the user explicitly chose the protocol.
	protocolExplicit := isFlagChanged(cmd, "protocol")
	if !protocolExplicit {
		baseConfig.protocolFilter = func(protocol string) bool {
			return isCredsProtocol(protocol)
		}
	}

	return runSubcommand(cmd, baseConfig)
}
