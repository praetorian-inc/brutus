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

  # Pre-paired user:pass combos (no Cartesian product)
  brutus creds --target 10.0.0.50:22 -c "admin:admin,root:toor,deploy:deploy123"

  # Credentials file (user:pass per line)
  brutus creds --target 10.0.0.50:3306 -C creds.txt

  # Targets file (auto-fingerprinted with Nerva)
  brutus creds --targets-file targets.txt -u admin -P passwords.txt

  # Pipeline mode with Nerva JSON (HTTP and SNMP services are skipped)
  naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt

  # Pipe URI targets (protocol from scheme, no fingerprinting needed)
  echo "ssh://192.168.1.10:22" | brutus creds -p "password,Password1"

  # Import targets from nmap XML scan
  brutus creds --nmap-file scan.xml -P passwords.txt

  # Import targets from masscan (requires --protocol or auto-fingerprints with Nerva)
  brutus creds --masscan-file scan.json --protocol ssh -P passwords.txt`,
	RunE: runCreds,
}

func init() {
	registerCredsFlags(credsCmd)
}

func runCreds(cmd *cobra.Command, args []string) error {
	base, err := buildBaseConfig(cmd)
	if err != nil {
		return err
	}

	// Load credentials (creds-specific)
	usernames, passwords, credPairs, err := loadCredentialInputs(cmd)
	if err != nil {
		return err
	}
	base.usernames = usernames
	base.passwords = passwords
	base.credentials = credPairs

	// Load SSH keys (creds-only)
	if keyErr := validateKeyFileFlags(flagKeyFile, isFlagChanged(cmd, "usernames"), flagUsernameFile); keyErr != nil {
		return keyErr
	}
	keys, err := loadKey(flagKeyFile)
	if err != nil {
		return err
	}

	// Creds mode: disable irrelevant features
	base.aiMode = false
	base.useBadkeys = false
	base.badkeysOnly = false

	// In pipeline/fingerprint mode, skip HTTP-like and SNMP protocols.
	if !isFlagChanged(cmd, "protocol") {
		base.protocolFilter = creds.IsCredsProtocol
	}

	return runSubcommand(cmd, &runConfig{baseConfigOptions: base, keys: keys})
}
