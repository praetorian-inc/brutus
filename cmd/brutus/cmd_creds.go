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

	"github.com/praetorian-inc/brutus/pkg/brutus/creds"
)

var credsCmd = &cobra.Command{
	Use:     "creds",
	Aliases: []string{"services", "defaults", "credentials"},
	Short:   "Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)",
	Long: `Audit default and weak credentials across network services, databases,
and enterprise protocols such as SSH, RDP, MySQL, PostgreSQL, SMB, LDAP,
Redis, and more.

For SNMP community string testing, use "brutus snmp" instead.
If --protocol http is explicitly set, only HTTP Basic Auth with default
credentials will be tested. For full web panel auditing including form-based
login and AI-powered detection, use "brutus web" instead.

In pipeline/fingerprint mode, HTTP and SNMP services are automatically skipped.`,
	Example: `  # Single target
  brutus creds --target 192.168.1.10:22 --protocol ssh -p "password,Password1"

  # Targets file (auto-fingerprinted with Nerva)
  brutus creds --targets-file targets.txt -u admin -P passwords.txt

  # Pipeline mode with Nerva JSON (HTTP and SNMP services are skipped)
  naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt

  # Pipe plain targets (auto-fingerprinted with Nerva)
  cat targets.txt | brutus creds

  # Pipe URI targets (protocol from scheme, no fingerprinting needed)
  echo "ssh://192.168.1.10:22" | brutus creds -p "password,Password1"`,
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

	// Creds mode never uses AI browser automation, sticky keys, or badkeys
	// (badkeys has its own subcommand now)
	baseConfig.aiMode = false
	baseConfig.stickyKeys = false
	baseConfig.useBadkeys = false
	baseConfig.badkeysOnly = false

	// In pipeline/fingerprint mode, skip HTTP-like protocols.
	// If --protocol is explicitly set to http, we still allow it (basic auth only)
	// but don't install a filter since the user explicitly chose the protocol.
	protocolExplicit := isFlagChanged(cmd, "protocol")
	if !protocolExplicit {
		baseConfig.protocolFilter = creds.IsCredsProtocol
	}

	return runSubcommand(cmd, baseConfig)
}
