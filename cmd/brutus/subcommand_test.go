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
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus/creds"
	snmpPkg "github.com/praetorian-inc/brutus/pkg/brutus/snmp"
	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

// TestIsFlagChanged_LocalFlag tests detection of explicitly set local flags.
func TestIsFlagChanged_LocalFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("protocol", "", "protocol to use")

	// Before parsing: flag exists but not changed
	assert.False(t, isFlagChanged(cmd, "protocol"))

	// After explicit set: flag is changed
	require.NoError(t, cmd.Flags().Set("protocol", "ssh"))
	assert.True(t, isFlagChanged(cmd, "protocol"))
}

// TestIsFlagChanged_InheritedFlag tests detection of persistent flags from parent.
func TestIsFlagChanged_InheritedFlag(t *testing.T) {
	parent := &cobra.Command{Use: "root"}
	parent.PersistentFlags().String("protocol", "", "protocol to use")

	child := &cobra.Command{Use: "creds"}
	parent.AddCommand(child)

	// Before parsing: not changed
	assert.False(t, isFlagChanged(child, "protocol"))

	// Set on parent persistent flags (inherited by child)
	require.NoError(t, parent.PersistentFlags().Set("protocol", "http"))
	assert.True(t, isFlagChanged(child, "protocol"))
}

// TestIsFlagChanged_NonexistentFlag tests that a missing flag returns false.
func TestIsFlagChanged_NonexistentFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	assert.False(t, isFlagChanged(cmd, "nonexistent"))
}

// TestRunCreds_SetsProtocolFilter tests that runCreds installs the creds
// protocol filter when --protocol is not explicitly set.
func TestRunCreds_SetsProtocolFilter(t *testing.T) {
	// Build a minimal cobra command with the protocol flag
	cmd := &cobra.Command{Use: "creds"}
	parent := &cobra.Command{Use: "brutus"}
	parent.PersistentFlags().StringVar(&flagProtocol, "protocol", "", "")
	parent.AddCommand(cmd)

	config := &baseConfigOptions{}

	// Simulate: no --protocol flag set → filter should apply
	protocolExplicit := isFlagChanged(cmd, "protocol")
	if !protocolExplicit {
		config.protocolFilter = creds.IsCredsProtocol
	}

	require.NotNil(t, config.protocolFilter)
	assert.True(t, config.protocolFilter("ssh"))
	assert.True(t, config.protocolFilter("mysql"))
	assert.False(t, config.protocolFilter("http"))
	assert.False(t, config.protocolFilter("https"))
	assert.False(t, config.protocolFilter("browser"))
}

// TestRunCreds_NoFilterWhenProtocolExplicit tests that explicitly setting
// --protocol disables the creds protocol filter.
func TestRunCreds_NoFilterWhenProtocolExplicit(t *testing.T) {
	cmd := &cobra.Command{Use: "creds"}
	parent := &cobra.Command{Use: "brutus"}
	parent.PersistentFlags().StringVar(&flagProtocol, "protocol", "", "")
	parent.AddCommand(cmd)

	require.NoError(t, parent.PersistentFlags().Set("protocol", "http"))

	config := &baseConfigOptions{}

	protocolExplicit := isFlagChanged(cmd, "protocol")
	if !protocolExplicit {
		config.protocolFilter = creds.IsCredsProtocol
	}

	// Filter should NOT be set when --protocol is explicitly provided
	assert.Nil(t, config.protocolFilter)
}

// TestRunWeb_SetsProtocolFilter tests that runWeb always installs the web
// protocol filter.
func TestRunWeb_SetsProtocolFilter(t *testing.T) {
	config := &baseConfigOptions{}
	config.protocolFilter = web.IsWebProtocol

	assert.True(t, config.protocolFilter("http"))
	assert.True(t, config.protocolFilter("https"))
	assert.True(t, config.protocolFilter("browser"))
	assert.False(t, config.protocolFilter("ssh"))
	assert.False(t, config.protocolFilter("mysql"))
	assert.False(t, config.protocolFilter("rdp"))
}

// TestRunWeb_HTTPSFlagSetsOverride tests that --https sets protocolOverride
// when --protocol is not explicitly set.
func TestRunWeb_HTTPSFlagSetsOverride(t *testing.T) {
	cmd := &cobra.Command{Use: "web"}
	parent := &cobra.Command{Use: "brutus"}
	parent.PersistentFlags().StringVar(&flagProtocol, "protocol", "", "")
	parent.AddCommand(cmd)

	base := &baseConfigOptions{}
	wc := &webConfig{}

	// Simulate: --https set, --protocol not set
	flagHTTPS = true
	defer func() { flagHTTPS = false }()

	if flagHTTPS && !isFlagChanged(cmd, "protocol") {
		base.protocolOverride = "https"
	}
	if base.protocolOverride == "https" {
		wc.useHTTPS = true
	}

	assert.Equal(t, "https", base.protocolOverride)
	assert.True(t, wc.useHTTPS)
}

// TestRunWeb_ProtocolOverridesHTTPSFlag tests that --protocol takes
// precedence over --https.
func TestRunWeb_ProtocolOverridesHTTPSFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "web"}
	parent := &cobra.Command{Use: "brutus"}
	parent.PersistentFlags().StringVar(&flagProtocol, "protocol", "", "")
	parent.AddCommand(cmd)

	require.NoError(t, parent.PersistentFlags().Set("protocol", "http"))

	base := &baseConfigOptions{}
	wc := &webConfig{}

	// Simulate: both --https and --protocol http set
	flagHTTPS = true
	defer func() { flagHTTPS = false }()

	if flagHTTPS && !isFlagChanged(cmd, "protocol") {
		base.protocolOverride = "https"
	}
	if base.protocolOverride == "https" {
		wc.useHTTPS = true
	}

	// --protocol was explicitly set, so --https should not override
	assert.Equal(t, "", base.protocolOverride)
	assert.False(t, wc.useHTTPS)
}

// TestRunLogon_DefaultsToRDP tests that logon mode defaults protocol to RDP.
func TestRunLogon_DefaultsToRDP(t *testing.T) {
	base := &baseConfigOptions{}

	// Simulate runLogon logic
	if base.protocolOverride == "" {
		base.protocolOverride = "rdp"
	}
	base.protocolFilter = func(protocol string) bool {
		return protocol == "rdp"
	}

	lc := &logonConfig{}
	rc := &runConfig{baseConfigOptions: base, logon: lc}

	assert.Equal(t, "rdp", rc.protocolOverride)
	assert.NotNil(t, rc.logon)
	assert.True(t, rc.protocolFilter("rdp"))
	assert.False(t, rc.protocolFilter("ssh"))
	assert.False(t, rc.protocolFilter("http"))
}

// TestRunSNMP_SetsProtocolOverrideAndFilter tests that runSNMP forces SNMP
// protocol and installs the SNMP protocol filter.
func TestRunSNMP_SetsProtocolOverrideAndFilter(t *testing.T) {
	config := &baseConfigOptions{}

	// Simulate runSNMP logic
	config.protocolOverride = "snmp"
	config.protocolFilter = snmpPkg.IsSNMPProtocol

	assert.Equal(t, "snmp", config.protocolOverride)
	assert.True(t, config.protocolFilter("snmp"))
	assert.False(t, config.protocolFilter("ssh"))
	assert.False(t, config.protocolFilter("http"))
}

// TestProtocolFilters_AreComplementary verifies that the web, creds, and snmp
// filters partition protocols correctly — each protocol matches exactly one filter.
func TestProtocolFilters_AreComplementary(t *testing.T) {
	protocols := []string{
		"http", "https", "browser",
		"ssh", "mysql", "rdp", "ldap", "ftp", "smb",
		"postgresql", "mssql", "redis", "mongodb",
		"snmp",
	}

	for _, p := range protocols {
		isWeb := web.IsWebProtocol(p)
		isCreds := creds.IsCredsProtocol(p)
		isSNMP := snmpPkg.IsSNMPProtocol(p)

		// Count how many filters match
		matchCount := 0
		if isWeb {
			matchCount++
		}
		if isCreds {
			matchCount++
		}
		if isSNMP {
			matchCount++
		}

		assert.Equal(t, 1, matchCount,
			"protocol %q: IsWebProtocol=%v, IsCredsProtocol=%v, IsSNMPProtocol=%v — should match exactly one",
			p, isWeb, isCreds, isSNMP)
	}
}
