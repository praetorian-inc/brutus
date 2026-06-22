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
//  1. "stickykeys" resolves to its own command (stickykeysCmd) with Use "stickykeys".
//  2. "utilman" resolves to its own command (utilmanCmd) with Use "utilman".
//  3. stickykeysCmd and utilmanCmd are distinct commands.
//  4. Former aliases ("sticky-keys", "sethc", "accessibility", "ease-of-access",
//     "winlogon") no longer resolve to any command.
//  5. logonCmd no longer claims any of the single-check names.
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

	// --- former stickykeysCmd aliases (removed) ---

	t.Run("sticky-keys_no_longer_an_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"sticky-keys"})
		assert.Error(t, err,
			"'sticky-keys' must not resolve to any command after the alias was removed")
	})

	t.Run("sethc_no_longer_an_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"sethc"})
		assert.Error(t, err,
			"'sethc' must not resolve to any command after the alias was removed")
	})

	// --- former utilmanCmd aliases (removed) ---

	t.Run("accessibility_no_longer_an_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"accessibility"})
		assert.Error(t, err,
			"'accessibility' must not resolve to any command after the alias was removed")
	})

	t.Run("ease-of-access_no_longer_an_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"ease-of-access"})
		assert.Error(t, err,
			"'ease-of-access' must not resolve to any command after the alias was removed")
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
		_, _, err := rootCmd.Find([]string{"sethc"})
		assert.Error(t, err,
			"'sethc' must not resolve to any command after the alias was removed")
	})

	t.Run("logon_does_not_claim_accessibility_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"accessibility"})
		assert.Error(t, err,
			"'accessibility' must not resolve to any command after the alias was removed")
	})

	// winlogon is no longer an alias for any command; cobra returns an error for it.
	t.Run("winlogon_no_longer_an_alias", func(t *testing.T) {
		_, _, err := rootCmd.Find([]string{"winlogon"})
		assert.Error(t, err,
			"'winlogon' must not resolve to any command after the alias was removed")
	})
}
