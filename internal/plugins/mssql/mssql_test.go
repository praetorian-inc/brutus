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

package mssql

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// getTestConfig returns test configuration from environment variables
// Returns empty strings if not configured (test should skip)
func getTestConfig() (host, user, pass string) {
	host = os.Getenv("MSSQL_TEST_HOST")
	user = os.Getenv("MSSQL_TEST_USER")
	pass = os.Getenv("MSSQL_TEST_PASS")
	return
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "mssql", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no MSSQL server configured
	// Configure via MSSQL_TEST_HOST, MSSQL_TEST_USER, MSSQL_TEST_PASS
	host, user, pass := getTestConfig()
	if host == "" {
		t.Skip("Skipping: MSSQL_TEST_HOST not configured")
	}

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mssql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success, "Expected successful authentication")
	assert.Nil(t, result.Error, "Expected no error on successful auth")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no MSSQL server configured
	host, user, _ := getTestConfig()
	if host == "" {
		t.Skip("Skipping: MSSQL_TEST_HOST not configured")
	}

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, "wrongpassword", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mssql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success, "Expected failed authentication")
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have MSSQL running
	result := p.Test(ctx, "localhost:9999", "sa", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mssql", result.Protocol)
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
	result := p.Test(ctx, "127.0.0.1:1", "sa", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mssql", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
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

	result := p.Test(ctx, "localhost:1433", "sa", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected timeout failure")
	assert.NotNil(t, result.Error, "Timeout should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	timeout := 5 * time.Second

	result := p.Test(ctx, "localhost:1433", "sa", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected context cancellation failure")
	assert.NotNil(t, result.Error, "Context cancellation should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	// Verify that the plugin can be instantiated
	p := &Plugin{}
	assert.NotNil(t, p)
	assert.Equal(t, "mssql", p.Name())
}
