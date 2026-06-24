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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetRestrictedAdminFlags resets all global flag vars touched by the
// Restricted Admin command to their zero values so subtests do not bleed state
// into each other. Also resets persistent flags that are relevant to the scan
// path (flagJSON, flagOutputFile).
func resetRestrictedAdminFlags() {
	flagRAUsername = ""
	flagRAPassword = ""
	flagRAHash = ""
	flagRADomain = ""
	flagWeb = false
	flagOpen = false
	flagTarget = ""
	flagTargetsFile = ""
	flagJSON = false
	flagOutputFile = ""
}

// =============================================================================
// 1. Command wiring
// =============================================================================

// TestRestrictedAdminCmd_Wiring verifies that the "restrictedadmin" subcommand
// is registered under the "logon" command and that both canonical names and
// declared aliases resolve to the same command object.
func TestRestrictedAdminCmd_Wiring(t *testing.T) {
	t.Run("restrictedadmin_resolves_via_logon", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"logon", "restrictedadmin"})
		require.NoError(t, err, "rootCmd.Find must not error for 'logon restrictedadmin'")
		require.NotNil(t, cmd, "'logon restrictedadmin' must resolve to a command")
		assert.Equal(t, "restrictedadmin", cmd.Use,
			"resolved command Use must be 'restrictedadmin'")
		assert.Same(t, restrictedAdminCmd, cmd,
			"resolved command must be restrictedAdminCmd")
	})

	t.Run("alias_restricted-admin_resolves", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"logon", "restricted-admin"})
		require.NoError(t, err, "rootCmd.Find must not error for alias 'restricted-admin'")
		require.NotNil(t, cmd)
		assert.Equal(t, "restrictedadmin", cmd.Use,
			"alias 'restricted-admin' must resolve to command with Use 'restrictedadmin'")
	})

	t.Run("alias_ram_resolves", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"logon", "ram"})
		require.NoError(t, err, "rootCmd.Find must not error for alias 'ram'")
		require.NotNil(t, cmd)
		assert.Equal(t, "restrictedadmin", cmd.Use,
			"alias 'ram' must resolve to command with Use 'restrictedadmin'")
	})

	t.Run("all_aliases_resolve_to_same_command", func(t *testing.T) {
		canonical, _, err1 := rootCmd.Find([]string{"logon", "restrictedadmin"})
		aliasHyphen, _, err2 := rootCmd.Find([]string{"logon", "restricted-admin"})
		aliasRam, _, err3 := rootCmd.Find([]string{"logon", "ram"})
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NoError(t, err3)
		assert.Same(t, canonical, aliasHyphen, "restricted-admin alias must point to same command")
		assert.Same(t, canonical, aliasRam, "ram alias must point to same command")
	})
}

// =============================================================================
// 2. Web-login flag validation (driven via runRestrictedAdmin dispatcher)
// =============================================================================

// TestRestrictedAdminCmd_WebValidation exercises the flag-validation logic in
// runRestrictedAdminWeb (called when --web is set). State is controlled via
// global flag vars, which are reset before each subtest.
func TestRestrictedAdminCmd_WebValidation(t *testing.T) {
	// Drive validation through the real run function so the tests exercise
	// actual behaviour, not just internal helpers.
	run := func() error {
		return runRestrictedAdmin(restrictedAdminCmd, nil)
	}

	t.Run("web_without_target_requires_target", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagWeb = true
		// flagTarget intentionally left empty.
		err := run()
		require.Error(t, err)
		assert.ErrorContains(t, err, "requires --target",
			"missing --target when --web must report 'requires --target'")
	})

	t.Run("web_with_target_no_credentials", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagWeb = true
		flagTarget = "host:3389"
		flagRAUsername = "admin"
		// Neither password nor hash set.
		err := run()
		require.Error(t, err)
		assert.ErrorContains(t, err, "password or NT hash is required",
			"missing credentials must report 'password or NT hash is required'")
	})

	t.Run("web_password_and_hash_are_mutually_exclusive", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagWeb = true
		flagTarget = "host:3389"
		flagRAUsername = "admin"
		flagRAPassword = "secret"
		flagRAHash = "aad3b435b51404eeaad3b435b51404ee" // valid 32-char hex
		err := run()
		require.Error(t, err)
		assert.ErrorContains(t, err, "mutually exclusive",
			"supplying both --password and --hash must report 'mutually exclusive'")
	})

	t.Run("web_hash_too_short_reports_32_or_hex", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagWeb = true
		flagTarget = "host:3389"
		flagRAUsername = "admin"
		flagRAHash = "deadbeef" // only 8 chars, too short
		err := run()
		require.Error(t, err)
		// NormalizeNTHash reports "32 hex characters (got 8)"; either "32" or
		// "hex" in the message is sufficient for this test.
		errMsg := err.Error()
		assert.True(t,
			strings.Contains(errMsg, "32") || strings.Contains(errMsg, "hex"),
			"short hash error must mention '32' or 'hex'; got: %q", errMsg,
		)
	})

	t.Run("open_without_web_requires_web", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagOpen = true
		flagWeb = false
		flagTarget = "host:3389"
		err := run()
		require.Error(t, err)
		assert.ErrorContains(t, err, "--open requires --web",
			"--open without --web must report '--open requires --web'")
	})
}

// =============================================================================
// 3. Web-login flag validation via rootCmd.SetArgs + Execute
// =============================================================================

// TestRestrictedAdminCmd_WebValidation_Execute exercises the same validation
// paths via the real cobra Execute path, matching the pattern used by
// TestEnumOracles_RequiresKnownValid and TestEnumTeamsAuth_NoFlagCollisionPanic.
func TestRestrictedAdminCmd_WebValidation_Execute(t *testing.T) {
	setup := func(t *testing.T, args []string) {
		t.Helper()
		// Reset global flag vars BEFORE executing so state from prior subtests
		// (which drove flags directly) does not leak into the Execute path.
		resetRestrictedAdminFlags()
		rootCmd.SetOut(io.Discard)
		rootCmd.SetErr(io.Discard)
		rootCmd.SetArgs(args)
		t.Cleanup(func() {
			rootCmd.SetArgs(nil)
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
			resetRestrictedAdminFlags()
		})
	}

	t.Run("web_without_target_via_execute", func(t *testing.T) {
		setup(t, []string{"logon", "restrictedadmin", "--web", "--username", "admin", "--password", "x"})
		err := rootCmd.Execute()
		require.Error(t, err)
		assert.ErrorContains(t, err, "requires --target")
	})

	t.Run("open_without_web_via_execute", func(t *testing.T) {
		setup(t, []string{"logon", "restrictedadmin", "--open", "--target", "host:3389"})
		err := rootCmd.Execute()
		require.Error(t, err)
		assert.ErrorContains(t, err, "--open requires --web")
	})
}

// =============================================================================
// 4. Target collection
// =============================================================================

// TestRestrictedAdminCmd_CollectTargets exercises collectRestrictedAdminTargets
// without making any network connections.
func TestRestrictedAdminCmd_CollectTargets(t *testing.T) {
	base := &baseConfigOptions{}

	t.Run("single_target_flag_returns_that_target", func(t *testing.T) {
		resetRestrictedAdminFlags()
		flagTarget = "10.0.0.1:3389"
		targets, err := collectRestrictedAdminTargets(base, false)
		require.NoError(t, err)
		require.Len(t, targets, 1)
		assert.Equal(t, "10.0.0.1:3389", targets[0])
	})

	t.Run("targets_file_returns_all_lines", func(t *testing.T) {
		resetRestrictedAdminFlags()

		// Write a temp file with two host:port lines.
		dir := t.TempDir()
		f := filepath.Join(dir, "targets.txt")
		content := "192.168.1.1:3389\n192.168.1.2:3389\n"
		require.NoError(t, os.WriteFile(f, []byte(content), 0o600))

		flagTargetsFile = f
		targets, err := collectRestrictedAdminTargets(base, false)
		require.NoError(t, err)
		require.Len(t, targets, 2)
		assert.Equal(t, "192.168.1.1:3389", targets[0])
		assert.Equal(t, "192.168.1.2:3389", targets[1])
	})

	t.Run("no_source_returns_error_containing_target_is_required", func(t *testing.T) {
		resetRestrictedAdminFlags()
		// No flagTarget, no flagTargetsFile, no nmap/masscan file, useStdin=false.
		_, err := collectRestrictedAdminTargets(base, false)
		require.Error(t, err)
		assert.ErrorContains(t, err, "--target is required",
			"missing target source must report '--target is required'")
	})
}
