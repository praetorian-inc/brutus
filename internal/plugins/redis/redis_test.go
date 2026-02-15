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

package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// getTestConfig returns test configuration from environment variables with defaults
func getTestConfig() (host, pass string) {
	host = os.Getenv("REDIS_TEST_HOST")
	if host == "" {
		host = "localhost:6379"
	}
	pass = os.Getenv("REDIS_TEST_PASS")
	if pass == "" {
		pass = "testpassword"
	}
	return
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "redis", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no Redis server available
	// This test requires a running Redis instance
	// Configure via REDIS_TEST_HOST, REDIS_TEST_PASS
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	host, pass := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, "", pass, timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success, "Expected successful authentication")
	assert.Nil(t, result.Error, "Expected no error on successful auth")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no Redis server available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	host, _ := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, "", "wrongpassword", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success, "Expected failed authentication")
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_NoAuthRequired(t *testing.T) {
	// Skip in CI - this test is for local Redis without auth
	if testing.Short() || os.Getenv("CI") != "" {
		t.Skip("Skipping no-auth test in short mode or CI")
	}

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	// Try empty password on Redis with no auth required
	result := p.Test(ctx, "localhost:6379", "", "", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "localhost:6379", result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, "", result.Password)
	// If Redis has no auth, this should succeed
	// If Redis requires auth, this should fail with nil error (auth failure)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have Redis running
	result := p.Test(ctx, "localhost:9999", "", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "Connection error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use an invalid hostname
	result := p.Test(ctx, "invalid.host.nonexistent:6379", "", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "invalid.host.nonexistent:6379", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "DNS error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Very short timeout to force timeout error
	timeout := 1 * time.Nanosecond

	result := p.Test(ctx, "localhost:6379", "", "password", timeout)

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected timeout failure")
	assert.NotNil(t, result.Error, "Timeout should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	timeout := 5 * time.Second

	result := p.Test(ctx, "localhost:6379", "", "password", timeout)

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected context cancellation failure")
	assert.NotNil(t, result.Error, "Context cancellation should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Target without port (should use default 6379 or fail)
	result := p.Test(ctx, "localhost", "", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	// Connection may fail or succeed depending on implementation
	// Just verify we get a valid result structure
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestInit(t *testing.T) {
	// Verify that the plugin registers itself
	// This test ensures init() was called
	// We can't directly test init(), but we can verify the plugin is registered
	// by checking that plugin.Register was called (indirectly)

	// Just verify the plugin can be instantiated
	p := &Plugin{}
	assert.NotNil(t, p)
	assert.Equal(t, "redis", p.Name())
}
