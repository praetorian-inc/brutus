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

package ldap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "ldap", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no LDAP server available
	// In real tests, use Docker container with known credentials
	t.Skip("Integration test - requires LDAP server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:389", "admin", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "ldap", result.Protocol)
	assert.Equal(t, "localhost:389", result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no LDAP server available
	t.Skip("Integration test - requires LDAP server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:389", "admin", "wrongpassword", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "ldap", result.Protocol)
	assert.Equal(t, "localhost:389", result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "admin", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "ldap", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires LDAP server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, "localhost:389", "admin", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:389", "admin", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestClassifyError_AuthFailure(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected error
	}{
		{
			name:     "Invalid Credentials",
			errMsg:   "LDAP Result Code 49 \"Invalid Credentials\"",
			expected: nil, // Auth failure returns nil
		},
		{
			name:     "Invalid credentials lowercase",
			errMsg:   "invalid credentials",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &mockError{msg: tt.errMsg}
			result := classifyError(err)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestClassifyError_ConnectionError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{
			name:   "Connection refused",
			errMsg: "connection refused",
		},
		{
			name:   "No route to host",
			errMsg: "no route to host",
		},
		{
			name:   "Timeout",
			errMsg: "i/o timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &mockError{msg: tt.errMsg}
			result := classifyError(err)
			assert.NotNil(t, result)
			assert.Contains(t, result.Error(), "connection error")
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		expectedHost string
		expectedPort string
	}{
		{
			name:         "With port 389",
			target:       "localhost:389",
			expectedHost: "localhost",
			expectedPort: "389",
		},
		{
			name:         "With port 636",
			target:       "ldap.example.com:636",
			expectedHost: "ldap.example.com",
			expectedPort: "636",
		},
		{
			name:         "No port - defaults to 389",
			target:       "localhost",
			expectedHost: "localhost",
			expectedPort: "389",
		},
		{
			name:         "IP with port",
			target:       "192.168.1.1:10389",
			expectedHost: "192.168.1.1",
			expectedPort: "10389",
		},
		{
			name:         "IP without port",
			target:       "192.168.1.1",
			expectedHost: "192.168.1.1",
			expectedPort: "389",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := brutus.ParseTarget(tt.target, "389")
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

// mockError is a simple error implementation for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
