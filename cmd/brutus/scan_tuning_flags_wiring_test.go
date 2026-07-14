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

// scanTuningFlagNames lists the flags moved off rootCmd's persistent flags
// onto each target-based scan command via registerScanTuningFlags, so that
// the enum subtree does not inherit them.
var scanTuningFlagNames = []string{"connect-timeout", "mode", "retries"}

// TestScanTuningFlags_NotOnRoot verifies that --connect-timeout, --mode, and
// --retries (and the -m shorthand) are no longer registered as persistent
// flags on rootCmd.
func TestScanTuningFlags_NotOnRoot(t *testing.T) {
	for _, name := range scanTuningFlagNames {
		name := name
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, rootCmd.PersistentFlags().Lookup(name),
				"rootCmd must not have --%s as a persistent flag", name)
		})
	}

	assert.Nil(t, rootCmd.PersistentFlags().ShorthandLookup("m"),
		"rootCmd must not have -m as a persistent flag shorthand")
}

// TestScanTuningFlags_OnScanCommands verifies that each target-based scan
// command registers all three scan-tuning flags via registerScanTuningFlags.
func TestScanTuningFlags_OnScanCommands(t *testing.T) {
	scanCmds := map[string]*cobra.Command{
		"creds":      credsCmd,
		"web":        webCmd,
		"snmp":       snmpCmd,
		"badkeys":    badkeysCmd,
		"logon":      logonCmd,
		"stickykeys": stickykeysCmd,
		"utilman":    utilmanCmd,
	}

	for cmdName, cmd := range scanCmds {
		cmdName, cmd := cmdName, cmd
		t.Run(cmdName, func(t *testing.T) {
			for _, name := range scanTuningFlagNames {
				assert.NotNil(t, cmd.PersistentFlags().Lookup(name),
					"%s command must register --%s via registerScanTuningFlags", cmdName, name)
			}
		})
	}
}

// TestScanTuningFlags_NotInheritedByEnumLeaf verifies that an enum leaf
// command (enumGithubCmd) neither inherits nor directly registers any of the
// scan-tuning flags, confirming the enum subtree is isolated from them.
func TestScanTuningFlags_NotInheritedByEnumLeaf(t *testing.T) {
	for _, name := range scanTuningFlagNames {
		name := name
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, enumGithubCmd.InheritedFlags().Lookup(name),
				"enumGithubCmd must not inherit --%s", name)
			assert.Nil(t, enumGithubCmd.Flags().Lookup(name),
				"enumGithubCmd must not directly register --%s", name)
		})
	}
}
