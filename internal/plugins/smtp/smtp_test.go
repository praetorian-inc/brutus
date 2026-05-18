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

package smtp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "smtp", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no SMTP server available
	// In real tests, use Docker container with known credentials
	t.Skip("Integration test - requires SMTP server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:587", "user@example.com", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, "localhost:587", result.Target)
	assert.Equal(t, "user@example.com", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no SMTP server available
	t.Skip("Integration test - requires SMTP server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:587", "user@example.com", "wrongpassword", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, "localhost:587", result.Target)
	assert.Equal(t, "user@example.com", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "user@example.com", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires SMTP server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, "localhost:587", "user@example.com", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:587", "user@example.com", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestClassifyError_AuthenticationFailure(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected error
	}{
		{
			name:     "535 authentication failed",
			errMsg:   "535 5.7.8 Error: authentication failed",
			expected: nil, // Auth failure returns nil
		},
		{
			name:     "535 Authentication credentials invalid",
			errMsg:   "535 Authentication credentials invalid",
			expected: nil,
		},
		{
			name:     "invalid username or password",
			errMsg:   "invalid username or password",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple error with the message
			testErr := &mockError{msg: tt.errMsg}
			result := classifyError(testErr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClassifyError_ConnectionError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{
			name:   "connection refused",
			errMsg: "connection refused",
		},
		{
			name:   "timeout",
			errMsg: "i/o timeout",
		},
		{
			name:   "tls handshake failed",
			errMsg: "tls: handshake failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testErr := &mockError{msg: tt.errMsg}
			result := classifyError(testErr)
			assert.NotNil(t, result)
			assert.Contains(t, result.Error(), "connection error")
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
