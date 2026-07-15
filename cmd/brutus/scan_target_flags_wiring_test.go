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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// Tests that the host:port target-input flags are registered on the scan
// commands and NOT globally on rootCmd, so the enum subtree does not inherit
// them. Regression guard for the flag move out of registerSharedFlags.

func TestScanTargetFlags_NotOnRoot(t *testing.T) {
	names := []string{"target", "targets-file", "nmap-file", "masscan-file"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, rootCmd.PersistentFlags().Lookup(name))
		})
	}
}

func TestScanTargetFlags_OnScanCommands(t *testing.T) {
	names := []string{"target", "targets-file", "nmap-file", "masscan-file"}
	commands := map[string]*cobra.Command{
		"creds":      credsCmd,
		"web":        webCmd,
		"snmp":       snmpCmd,
		"badkeys":    badkeysCmd,
		"logon":      logonCmd,
		"stickykeys": stickykeysCmd,
		"utilman":    utilmanCmd,
	}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			for _, flagName := range names {
				assert.NotNil(t, cmd.PersistentFlags().Lookup(flagName), "expected flag %q on command %q", flagName, name)
			}
		})
	}
}

func TestScanTargetFlags_NotInheritedByEnumLeaf(t *testing.T) {
	names := []string{"target", "targets-file", "nmap-file", "masscan-file"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, enumGithubCmd.InheritedFlags().Lookup(name))
			assert.Nil(t, enumGithubCmd.Flags().Lookup(name))
		})
	}
}
