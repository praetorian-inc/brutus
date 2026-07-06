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
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetLogonFlags resets flagNoNLAProbe, flagFast, and flagScanTimeout to their
// defaults so each subtest starts from a clean state. Cobra bool/duration flags
// are sticky across ParseFlags calls (a re-parse with no args does not unset
// them), so we reset the backing package vars directly.
func resetLogonFlags() {
	flagNoNLAProbe = false
	flagFast = false
	flagScanTimeout = 10 * time.Second
}

// resetTimeoutFlag resets the persistent --timeout flag on rootCmd to its
// default (10s) and marks it unchanged so subsequent tests start clean.
func resetTimeoutFlag(t *testing.T) {
	t.Helper()
	require.NoError(t, rootCmd.PersistentFlags().Set("timeout", "10s"))
	// Mark it unchanged by looking it up and resetting the Changed bit.
	if f := rootCmd.PersistentFlags().Lookup("timeout"); f != nil {
		f.Changed = false
	}
}

// TestLogonFlagsWiring verifies that --no-nla-probe is wired through cobra
// into baseConfigOptions via buildBaseConfig.
func TestLogonFlagsWiring(t *testing.T) {
	// Always restore flags to their default state after the whole test.
	t.Cleanup(resetLogonFlags)

	t.Run("defaults_are_false", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{}))

		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.False(t, base.noNLAProbe,
			"base.noNLAProbe must default to false (--no-nla-probe not passed)")
	})

	t.Run("no_nla_probe_set_to_true", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{"--no-nla-probe"}))

		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.True(t, base.noNLAProbe,
			"base.noNLAProbe must be true after parsing --no-nla-probe")
	})
}

// TestFastFlagWiring verifies that --fast is registered on logon/stickykeys/
// utilman commands, defaults to false, wires through to base.fast via
// buildBaseConfig, and that the help text states the never-clean semantics.
//
// RED until the developer:
//  1. Adds `flagFast bool` to flags.go in the Logon flags block.
//  2. Adds `cmd.Flags().BoolVar(&flagFast, "fast", false, "...")` in registerLogonFlags.
//  3. Adds `fast bool` field to baseConfigOptions (config.go).
//  4. Adds `fast: flagFast` to buildBaseConfig return.
func TestFastFlagWiring(t *testing.T) {
	t.Cleanup(resetLogonFlags)
	t.Run("default_false", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{}))
		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.False(t, base.fast, "fast defaults false")
	})
	t.Run("set_true", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{"--fast"}))
		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.True(t, base.fast, "--fast sets base.fast")
	})
	t.Run("registered_on_all_three", func(t *testing.T) {
		for _, c := range []*cobra.Command{logonCmd, stickykeysCmd, utilmanCmd} {
			assert.NotNil(t, c.Flags().Lookup("fast"), "%s must register --fast", c.Use)
		}
	})
	t.Run("help_text_states_never_clean", func(t *testing.T) {
		f := logonCmd.Flags().Lookup("fast")
		require.NotNil(t, f)
		assert.Contains(t, f.Usage, "never clean", "help text must state the never-clean semantics")
	})
}

// TestConnectTimeoutFlagWiring verifies that --connect-timeout is wired through
// cobra into baseConfigOptions via buildBaseConfig.
//
// --connect-timeout is a shared persistent flag (registered in
// registerSharedFlags) with a 3s default that applies to all subcommands
// including the logon family.
func TestConnectTimeoutFlagWiring(t *testing.T) {
	t.Cleanup(resetLogonFlags)

	t.Run("default_is_3s", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{}))
		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, base.connectTimeout,
			"connect-timeout must default to 3s")
	})

	t.Run("override_applies", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{"--connect-timeout", "7s"}))
		base, err := buildBaseConfig(logonCmd)
		require.NoError(t, err)
		assert.Equal(t, 7*time.Second, base.connectTimeout,
			"connect-timeout must reflect the parsed flag")
	})
}

// TestScanTimeoutFlagWiring verifies that --scan-timeout is wired through cobra
// into baseConfigOptions.timeout on the logon family (logon, stickykeys, utilman).
//
// The logon family hard-renames the per-host settle deadline from the global
// --timeout to a local --scan-timeout. buildBaseConfig detects the logon family
// by checking whether cmd.Flags().Lookup("scan-timeout") != nil and uses
// flagScanTimeout as the source of base.timeout in that case.
//
// Default is 10s (the logon-appropriate scan deadline); non-logon commands keep
// --timeout with its own presets (tested separately in
// TestTimeoutNotRejectedOnNonLogonCommands).
func TestScanTimeoutFlagWiring(t *testing.T) {
	t.Cleanup(resetLogonFlags)

	tests := []struct {
		name    string
		cmd     *cobra.Command
		args    []string
		want    time.Duration
		wantMsg string
	}{
		{
			name:    "logon_default_is_10s",
			cmd:     logonCmd,
			args:    []string{},
			want:    10 * time.Second,
			wantMsg: "logon base.timeout must default to 10s (from --scan-timeout default)",
		},
		{
			name:    "logon_scan_timeout_override_to_20s",
			cmd:     logonCmd,
			args:    []string{"--scan-timeout", "20s"},
			want:    20 * time.Second,
			wantMsg: "logon base.timeout must be 20s after --scan-timeout 20s",
		},
		{
			name:    "stickykeys_default_is_10s",
			cmd:     stickykeysCmd,
			args:    []string{},
			want:    10 * time.Second,
			wantMsg: "stickykeys base.timeout must default to 10s (from --scan-timeout default)",
		},
		{
			name:    "stickykeys_scan_timeout_override_to_30s",
			cmd:     stickykeysCmd,
			args:    []string{"--scan-timeout", "30s"},
			want:    30 * time.Second,
			wantMsg: "stickykeys base.timeout must be 30s after --scan-timeout 30s",
		},
		{
			name:    "utilman_default_is_10s",
			cmd:     utilmanCmd,
			args:    []string{},
			want:    10 * time.Second,
			wantMsg: "utilman base.timeout must default to 10s (from --scan-timeout default)",
		},
		{
			name:    "utilman_scan_timeout_override_to_25s",
			cmd:     utilmanCmd,
			args:    []string{"--scan-timeout", "25s"},
			want:    25 * time.Second,
			wantMsg: "utilman base.timeout must be 25s after --scan-timeout 25s",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetLogonFlags()
			require.NoError(t, tc.cmd.ParseFlags(tc.args))

			base, err := buildBaseConfig(tc.cmd)
			require.NoError(t, err)
			assert.Equal(t, tc.want, base.timeout, tc.wantMsg)
		})
	}
}

// TestTimeoutRejectedOnLogonFamily verifies that passing the global --timeout
// persistent flag to any logon-family command (logon, stickykeys, utilman)
// returns a hard error that points operators to --scan-timeout.
//
// The guard lives in each command's PreRunE (set by guardLogonTimeoutFlag) and
// checks c.Flags().Changed("timeout"). Because --timeout is a persistent flag
// on rootCmd, cobra merges it into the child's Flags() during ParseFlags; a
// subsequent c.Flags().Changed("timeout") call returns true and the PreRunE
// rejects it.
func TestTimeoutRejectedOnLogonFamily(t *testing.T) {
	for _, cmd := range []*cobra.Command{logonCmd, stickykeysCmd, utilmanCmd} {
		cmd := cmd // capture range var
		t.Run(cmd.Use+"_rejects_timeout_flag", func(t *testing.T) {
			resetLogonFlags()
			t.Cleanup(func() { resetTimeoutFlag(t) })

			// Parse --timeout on the logon command. cobra's mergePersistentFlags
			// folds the rootCmd persistent flags into cmd.Flags(), so ParseFlags
			// can find and mark --timeout as Changed on this command.
			require.NoError(t, cmd.ParseFlags([]string{"--timeout", "3s"}),
				"ParseFlags with --timeout must not error during parsing phase")

			// The guard is wired into PreRunE by guardLogonTimeoutFlag.
			require.NotNil(t, cmd.PreRunE,
				"%s must have a PreRunE guard installed by guardLogonTimeoutFlag", cmd.Use)

			err := cmd.PreRunE(cmd, nil)
			require.Error(t, err,
				"PreRunE on %q must return an error when --timeout was passed", cmd.Use)
			assert.Contains(t, err.Error(), "scan-timeout",
				"the error for %q must mention --scan-timeout so operators know the replacement flag", cmd.Use)
		})
	}
}

// TestTimeoutNotRejectedOnNonLogonCommands verifies that the --timeout flag
// remains accepted on non-logon commands (creds) and that buildBaseConfig
// propagates it to base.timeout as before. This guards against accidentally
// attaching the logon rejection guard to the shared persistent pre-run hook.
func TestTimeoutNotRejectedOnNonLogonCommands(t *testing.T) {
	t.Cleanup(func() {
		// Reset the persistent timeout to default so later tests are unaffected.
		_ = credsCmd.ParseFlags([]string{"--timeout", "10s"})
		if f := rootCmd.PersistentFlags().Lookup("timeout"); f != nil {
			f.Changed = false
		}
	})

	t.Run("creds_accepts_timeout_and_propagates", func(t *testing.T) {
		require.NoError(t, credsCmd.ParseFlags([]string{"--timeout", "5s"}),
			"--timeout must still be accepted on credsCmd without error")

		base, err := buildBaseConfig(credsCmd)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, base.timeout,
			"creds base.timeout must reflect --timeout 5s (non-logon command keeps --timeout)")
	})
}
