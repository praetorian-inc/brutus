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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogonSubcommandWiring verifies that the "logon scan modes" feature is
// wired correctly at the cobra command level:
//
//  1. "stickykeys" resolves to its own command (stickykeysCmd) with the expected
//     primary Use name and aliases ("sticky-keys", "sethc").
//  2. "utilman" resolves to its own command (utilmanCmd) with the expected
//     aliases ("accessibility", "ease-of-access").
//  3. All aliases resolve to the same command object as their primary Use.
//  4. stickykeysCmd and utilmanCmd are distinct commands.
//  5. logonCmd no longer claims the single-check aliases that now belong to
//     the new subcommands (stickykeys, sticky-keys, sethc, utilman, accessibility,
//     ease-of-access must NOT resolve to logonCmd).
//
// These tests are RED until the developer:
//   - Adds stickykeysCmd (Use "stickykeys", aliases "sticky-keys","sethc") to
//     rootCmd.
//   - Adds utilmanCmd (Use "utilman", aliases "accessibility","ease-of-access") to
//     rootCmd.
//   - Removes "stickykeys","sticky-keys","utilman","sethc","accessibility" from
//     logonCmd.Aliases (keeping only "winlogon").
func TestLogonSubcommandWiring(t *testing.T) {
	// rootCmd is built by init() in root.go. We probe it with Find, which is
	// cobra's own traversal: it walks the command tree looking for the first
	// argument, trying both Use and Aliases.

	t.Run("stickykeys_resolves_to_stickykeysCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"stickykeys"})
		require.NoError(t, err, "rootCmd.Find must not return an error for 'stickykeys'")
		require.NotNil(t, cmd, "'stickykeys' must resolve to a command")
		assert.Equal(t, "stickykeys", cmd.Use,
			"'stickykeys' must resolve to a command whose Use is 'stickykeys'")
	})

	t.Run("utilman_resolves_to_utilmanCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"utilman"})
		require.NoError(t, err, "rootCmd.Find must not return an error for 'utilman'")
		require.NotNil(t, cmd, "'utilman' must resolve to a command")
		assert.Equal(t, "utilman", cmd.Use,
			"'utilman' must resolve to a command whose Use is 'utilman'")
	})

	t.Run("stickykeys_and_utilman_are_distinct_commands", func(t *testing.T) {
		stickyCmd, _, err1 := rootCmd.Find([]string{"stickykeys"})
		utilCmd, _, err2 := rootCmd.Find([]string{"utilman"})
		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NotNil(t, stickyCmd)
		require.NotNil(t, utilCmd)
		assert.NotEqual(t, stickyCmd.Use, utilCmd.Use,
			"stickykeysCmd and utilmanCmd must be distinct cobra commands")
	})

	// --- stickykeysCmd aliases ---

	t.Run("sticky-keys_alias_resolves_to_stickykeysCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"sticky-keys"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.Equal(t, "stickykeys", cmd.Use,
			"'sticky-keys' alias must resolve to stickykeysCmd (Use='stickykeys')")
	})

	t.Run("sethc_alias_resolves_to_stickykeysCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"sethc"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.Equal(t, "stickykeys", cmd.Use,
			"'sethc' alias must resolve to stickykeysCmd (Use='stickykeys')")
	})

	// --- utilmanCmd aliases ---

	t.Run("accessibility_alias_resolves_to_utilmanCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"accessibility"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.Equal(t, "utilman", cmd.Use,
			"'accessibility' alias must resolve to utilmanCmd (Use='utilman')")
	})

	t.Run("ease-of-access_alias_resolves_to_utilmanCmd", func(t *testing.T) {
		// cobra returns an error for completely unknown names; after the developer
		// adds utilmanCmd with alias "ease-of-access", Find must succeed without error.
		cmd, _, err := rootCmd.Find([]string{"ease-of-access"})
		if err != nil {
			// The alias does not exist yet — this is the RED failure we expect.
			t.Fatalf("'ease-of-access' alias not found (must be added as alias of utilmanCmd): %v", err)
		}
		require.NotNil(t, cmd)
		assert.Equal(t, "utilman", cmd.Use,
			"'ease-of-access' alias must resolve to utilmanCmd (Use='utilman')")
	})

	// --- logonCmd must NOT own single-check aliases ---

	t.Run("logon_does_not_claim_stickykeys_alias", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"stickykeys"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.NotEqual(t, "logon", cmd.Use,
			"'stickykeys' must no longer resolve to logonCmd after the alias remap")
	})

	t.Run("logon_does_not_claim_utilman_alias", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"utilman"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.NotEqual(t, "logon", cmd.Use,
			"'utilman' must no longer resolve to logonCmd after the alias remap")
	})

	t.Run("logon_does_not_claim_sethc_alias", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"sethc"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.NotEqual(t, "logon", cmd.Use,
			"'sethc' must no longer resolve to logonCmd after the alias remap")
	})

	t.Run("logon_does_not_claim_accessibility_alias", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"accessibility"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.NotEqual(t, "logon", cmd.Use,
			"'accessibility' must no longer resolve to logonCmd after the alias remap")
	})

	// winlogon must still resolve to logonCmd (kept as its alias per plan).
	t.Run("winlogon_alias_still_resolves_to_logonCmd", func(t *testing.T) {
		cmd, _, err := rootCmd.Find([]string{"winlogon"})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		assert.Equal(t, "logon", cmd.Use,
			"'winlogon' alias must still resolve to logonCmd")
	})
}
