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

package postgresql

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// getTestConfig returns test configuration from environment variables with defaults
func getTestConfig() (host, user, pass string) {
	host = os.Getenv("POSTGRES_TEST_HOST")
	if host == "" {
		host = "localhost:5432"
	}
	user = os.Getenv("POSTGRES_TEST_USER")
	if user == "" {
		user = "postgres"
	}
	pass = os.Getenv("POSTGRES_TEST_PASS")
	if pass == "" {
		pass = "postgres"
	}
	return
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "postgresql", p.Name())
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool // true if should be classified as auth error (nil)
	}{
		{
			name:     "password authentication failed",
			errStr:   "password authentication failed for user \"postgres\"",
			wantAuth: true,
		},
		{
			name:     "role does not exist",
			errStr:   "role \"baduser\" does not exist",
			wantAuth: true,
		},
		{
			name:     "no pg_hba.conf entry",
			errStr:   "no pg_hba.conf entry for host \"127.0.0.1\"",
			wantAuth: true,
		},
		{
			name:     "connection error",
			errStr:   "connection refused",
			wantAuth: false,
		},
		{
			name:     "network error",
			errStr:   "no route to host",
			wantAuth: false,
		},
		{
			name:     "timeout error",
			errStr:   "context deadline exceeded",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &mockError{msg: tt.errStr}
			result := classifyError(err)

			if tt.wantAuth {
				assert.Nil(t, result, "auth errors should return nil")
			} else {
				assert.NotNil(t, result, "connection errors should be wrapped")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL server")

	host, user, pass := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success, "Expected successful authentication")
	assert.Nil(t, result.Error, "Expected no error on successful auth")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL server")

	host, user, _ := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, "wrongpassword", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success, "Expected failed authentication")
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have PostgreSQL running
	result := p.Test(ctx, "localhost:9999", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "Connection error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use an invalid hostname
	result := p.Test(ctx, "127.0.0.1:1", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "DNS error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Very short timeout to force timeout error
	timeout := 1 * time.Nanosecond

	result := p.Test(ctx, "localhost:5432", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected timeout failure")
	assert.NotNil(t, result.Error, "Timeout should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires PostgreSQL server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	timeout := 5 * time.Second

	result := p.Test(ctx, "localhost:5432", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected context cancellation failure")
	assert.NotNil(t, result.Error, "Context cancellation should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Target without port (should use default or fail)
	result := p.Test(ctx, "localhost", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	// Connection may fail or succeed depending on implementation
	// Just verify we get a valid result structure
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestInit(t *testing.T) {
	// Just verify the plugin can be instantiated
	p := &Plugin{}
	assert.NotNil(t, p)
	assert.Equal(t, "postgresql", p.Name())
}

// mockError is a simple error implementation for testing error classification
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
