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

package rdp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "rdp", p.Name())
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "admin", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:3389", "admin", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestParseDomainUsername(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		domain   string
		username string
	}{
		{
			name:     "plain username",
			input:    "admin",
			domain:   "",
			username: "admin",
		},
		{
			name:     "domain backslash username",
			input:    "CORP\\admin",
			domain:   "CORP",
			username: "admin",
		},
		{
			name:     "empty string",
			input:    "",
			domain:   "",
			username: "",
		},
		{
			name:     "multiple backslashes",
			input:    "CORP\\SUBDOMAIN\\admin",
			domain:   "CORP",
			username: "SUBDOMAIN\\admin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain, user := parseDomainUsername(tc.input)
			assert.Equal(t, tc.domain, domain)
			assert.Equal(t, tc.username, user)
		})
	}
}

func TestPlugin_Registration(t *testing.T) {
	// Verify the plugin is registered via init() and accessible through the registry.
	plugin, err := brutus.GetPlugin("rdp")
	require.NoError(t, err, "rdp plugin must be registered")
	assert.Equal(t, "rdp", plugin.Name())
}

func TestPlugin_ImplementsInterface(t *testing.T) {
	// Compile-time check that Plugin satisfies brutus.Plugin.
	var _ brutus.Plugin = (*Plugin)(nil)
}

func TestPlugin_DefaultCredentials(t *testing.T) {
	creds := brutus.DefaultCredentials("rdp")
	require.NotNil(t, creds, "rdp_defaults.txt must be loadable")
	assert.GreaterOrEqual(t, len(creds), 5, "wordlist should have at least 5 credential pairs")

	// Verify the first entry is the well-known administrator:password pair.
	assert.Equal(t, "administrator", creds[0].Username)
	assert.Equal(t, "password", creds[0].Password)

	// Verify all entries have non-empty usernames and passwords.
	for i, c := range creds {
		assert.NotEmpty(t, c.Username, "credential %d should have a username", i)
		assert.NotEmpty(t, c.Password, "credential %d should have a password", i)
	}
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context before calling Test.
	cancel()

	result := p.Test(ctx, "198.51.100.1:3389", "admin", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error, "canceled context should produce a connection error")
}

func TestPlugin_Test_ResultFields(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "127.0.0.1:1", "testuser", "testpass", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "testpass", result.Password)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0), "Duration should be set")
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name      string
		errMsg    string
		expectNil bool
	}{
		{
			name:      "auth failure: logon failed",
			errMsg:    "Logon failed for user admin",
			expectNil: true,
		},
		{
			name:      "auth failure: access denied",
			errMsg:    "Access denied",
			expectNil: true,
		},
		{
			name:      "auth failure: credssp",
			errMsg:    "CredSSP authentication error",
			expectNil: true,
		},
		{
			name:      "connection error: timeout",
			errMsg:    "connection timeout",
			expectNil: false,
		},
		{
			name:      "connection error: refused",
			errMsg:    "connection refused",
			expectNil: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyError(fmt.Errorf("%s", tc.errMsg))
			if tc.expectNil {
				assert.Nil(t, err, "auth failure should classify as nil error")
			} else {
				assert.NotNil(t, err, "connection error should remain non-nil")
			}
		})
	}
}
