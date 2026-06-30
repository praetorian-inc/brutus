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

var badkeysCmd = &cobra.Command{
	Use:     "badkeys",
	Aliases: []string{"keys", "ssh-keys", "badkey"},
	Short:   "Test known weak/compromised SSH keys against targets",
	Long: `Test targets for known weak, default, or compromised SSH private keys.

This includes vendor-embedded keys from appliances (F5, Barracuda, Cisco),
default keys from tools like Vagrant, and keys linked to specific CVEs.

The protocol is always SSH. In pipeline/fingerprint mode, only SSH services
are tested. No credential flags are needed — Brutus uses its embedded
collection of known bad keys.`,
	Example: `  # Single target
  brutus badkeys --target 192.168.1.10:22

  # Targets file (auto-fingerprinted, only SSH services tested)
  brutus badkeys --targets-file targets.txt

  # Pipeline mode
  naabu -host 10.0.0.0/24 -p 22 -silent | nerva --json | brutus badkeys

  # Pipe plain targets
  echo "192.168.1.10:22" | brutus badkeys

  # URI format
  echo "ssh://192.168.1.10:22" | brutus badkeys

  # Import targets from nmap XML scan (only SSH services tested)
  brutus badkeys --nmap-file scan.xml`,
	RunE: runBadkeys,
}

func init() {
	// No subcommand-specific flags — badkeys uses only global flags
	// (target, output, performance). Credentials are embedded.
}

func runBadkeys(cmd *cobra.Command, args []string) error {
	base, err := buildBaseConfig(cmd)
	if err != nil {
		return err
	}

	// Badkeys mode: SSH-only, embedded bad keys only
	base.protocolOverride = "ssh"
	base.badkeysOnly = true
	base.useBadkeys = true
	base.aiMode = false

	// In pipeline/fingerprint mode, only process SSH targets
	base.protocolFilter = func(protocol string) bool {
		return protocol == "ssh"
	}

	return runSubcommand(cmd, &runConfig{baseConfigOptions: base})
}
