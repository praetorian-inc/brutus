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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetLogonFlags resets flagNoNLAProbe to its default (false) so each subtest
// starts from a clean state. Cobra bool flags are sticky across ParseFlags
// calls (a re-parse with no args does not unset them), so we reset the backing
// package var directly.
func resetLogonFlags() {
	flagNoNLAProbe = false
}

// TestLogonFlagsWiring verifies that --no-nla-probe is wired through cobra
// into baseConfigOptions via buildBaseConfig.
//
// This test is RED until the developer:
//  1. Adds flagNoNLAProbe package var to flags.go
//  2. Registers --no-nla-probe in registerLogonFlags
//  3. Adds noNLAProbe field to baseConfigOptions (config.go)
//  4. Populates it in buildBaseConfig (flags.go)
//
// The pattern mirrors logon_subcommand_wiring_test.go.
func TestLogonFlagsWiring(t *testing.T) {
	// Always restore flags to their default state after the whole test.
	t.Cleanup(resetLogonFlags)

	t.Run("defaults_are_false", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{}))

		base := buildBaseConfig(logonCmd)
		assert.False(t, base.noNLAProbe,
			"base.noNLAProbe must default to false (--no-nla-probe not passed)")
	})

	t.Run("no_nla_probe_set_to_true", func(t *testing.T) {
		resetLogonFlags()
		require.NoError(t, logonCmd.ParseFlags([]string{"--no-nla-probe"}))

		base := buildBaseConfig(logonCmd)
		assert.True(t, base.noNLAProbe,
			"base.noNLAProbe must be true after parsing --no-nla-probe")
	})
}

// TestConnectTimeoutFlagWiring verifies that --connect-timeout is wired through
// cobra into baseConfigOptions via buildBaseConfig.
//
// This test is RED until the developer:
//  1. Adds flagConnectTimeout package var to flags.go (Performance block)
//  2. Registers --connect-timeout in registerSharedFlags with a 3s default
//  3. Adds connectTimeout field to baseConfigOptions (config.go)
//  4. Populates it in buildBaseConfig (flags.go)
func TestConnectTimeoutFlagWiring(t *testing.T) {
	t.Run("default_is_3s", func(t *testing.T) {
		require.NoError(t, logonCmd.ParseFlags([]string{}))
		base := buildBaseConfig(logonCmd)
		assert.Equal(t, 3*time.Second, base.connectTimeout,
			"connect-timeout must default to 3s")
	})
	t.Run("override_applies", func(t *testing.T) {
		require.NoError(t, logonCmd.ParseFlags([]string{"--connect-timeout", "7s"}))
		base := buildBaseConfig(logonCmd)
		assert.Equal(t, 7*time.Second, base.connectTimeout,
			"connect-timeout must reflect the parsed flag")
	})
}
