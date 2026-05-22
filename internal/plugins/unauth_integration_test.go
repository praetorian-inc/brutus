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

//go:build integration

// Integration tests for unauthenticated access detection.
// These tests run against real containerized services configured WITHOUT authentication.
//
// Run with: go test -tags=integration -v -run TestUnauth ./internal/plugins/...
//
// Required environment variables are set by the ci-unauth workflow.
package plugins

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"

	// Import plugins that implement UnauthChecker
	_ "github.com/praetorian-inc/brutus/internal/plugins/docker"
	_ "github.com/praetorian-inc/brutus/internal/plugins/elasticsearch"
	_ "github.com/praetorian-inc/brutus/internal/plugins/kubernetes"
	_ "github.com/praetorian-inc/brutus/internal/plugins/postgresql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/redis"
)

const unauthTimeout = 10 * time.Second

// TestUnauth_PostgreSQL verifies that CheckUnauth detects PostgreSQL trust authentication.
func TestUnauth_PostgreSQL(t *testing.T) {
	host := os.Getenv("UNAUTH_POSTGRES_HOST")
	if host == "" {
		t.Skip("UNAUTH_POSTGRES_HOST not set")
	}

	plug, err := brutus.GetPlugin("postgresql")
	require.NoError(t, err)

	checker, ok := plug.(brutus.UnauthChecker)
	require.True(t, ok, "postgresql plugin must implement UnauthChecker")

	ctx := context.Background()
	result := checker.CheckUnauth(ctx, host, unauthTimeout, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success, "should detect trust authentication")
	assert.Equal(t, "(unauthenticated)", result.Username)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "trust authentication")
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestUnauth_Redis verifies that CheckUnauth detects Redis without requirepass.
func TestUnauth_Redis(t *testing.T) {
	host := os.Getenv("UNAUTH_REDIS_HOST")
	if host == "" {
		t.Skip("UNAUTH_REDIS_HOST not set")
	}

	plug, err := brutus.GetPlugin("redis")
	require.NoError(t, err)

	checker, ok := plug.(brutus.UnauthChecker)
	require.True(t, ok, "redis plugin must implement UnauthChecker")

	ctx := context.Background()
	result := checker.CheckUnauth(ctx, host, unauthTimeout, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success, "should detect open Redis")
	assert.Equal(t, "(unauthenticated)", result.Username)
	assert.Equal(t, "redis", result.Protocol)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "Redis accessible without authentication")
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestUnauth_Elasticsearch verifies that CheckUnauth detects Elasticsearch without X-Pack security.
func TestUnauth_Elasticsearch(t *testing.T) {
	host := os.Getenv("UNAUTH_ELASTICSEARCH_HOST")
	if host == "" {
		t.Skip("UNAUTH_ELASTICSEARCH_HOST not set")
	}

	plug, err := brutus.GetPlugin("elasticsearch")
	require.NoError(t, err)

	checker, ok := plug.(brutus.UnauthChecker)
	require.True(t, ok, "elasticsearch plugin must implement UnauthChecker")

	ctx := context.Background()
	result := checker.CheckUnauth(ctx, host, unauthTimeout, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success, "should detect open Elasticsearch")
	assert.Equal(t, "(unauthenticated)", result.Username)
	assert.Equal(t, "elasticsearch", result.Protocol)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "Elasticsearch accessible without authentication")
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestUnauth_Docker verifies that CheckUnauthAccess detects an exposed Docker daemon API.
func TestUnauth_Docker(t *testing.T) {
	host := os.Getenv("UNAUTH_DOCKER_HOST")
	if host == "" {
		t.Skip("UNAUTH_DOCKER_HOST not set")
	}

	ctx := context.Background()
	result := brutus.CheckUnauthAccess(ctx, host, "docker", unauthTimeout, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success, "should detect exposed Docker daemon")
	assert.Equal(t, "(unauthenticated)", result.Username)
	assert.Equal(t, "docker", result.Protocol)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "Docker daemon API exposed without authentication")
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestUnauth_NegativeControl verifies that CheckUnauth does NOT produce false positives
// when the target is not listening.
func TestUnauth_NegativeControl(t *testing.T) {
	ctx := context.Background()
	timeout := 2 * time.Second

	// PostgreSQL
	t.Run("PostgreSQL", func(t *testing.T) {
		plug, err := brutus.GetPlugin("postgresql")
		require.NoError(t, err)
		checker, ok := plug.(brutus.UnauthChecker)
		require.True(t, ok, "postgresql plugin must implement UnauthChecker")
		result := checker.CheckUnauth(ctx, "127.0.0.1:1", timeout, brutus.PluginConfig{})
		require.NotNil(t, result)
		assert.False(t, result.Success, "should not detect unauth on closed port")
	})

	// Redis
	t.Run("Redis", func(t *testing.T) {
		plug, err := brutus.GetPlugin("redis")
		require.NoError(t, err)
		checker, ok := plug.(brutus.UnauthChecker)
		require.True(t, ok, "redis plugin must implement UnauthChecker")
		result := checker.CheckUnauth(ctx, "127.0.0.1:1", timeout, brutus.PluginConfig{})
		require.NotNil(t, result)
		assert.False(t, result.Success, "should not detect unauth on closed port")
	})

	// Elasticsearch
	t.Run("Elasticsearch", func(t *testing.T) {
		plug, err := brutus.GetPlugin("elasticsearch")
		require.NoError(t, err)
		checker, ok := plug.(brutus.UnauthChecker)
		require.True(t, ok, "elasticsearch plugin must implement UnauthChecker")
		result := checker.CheckUnauth(ctx, "127.0.0.1:1", timeout, brutus.PluginConfig{})
		require.NotNil(t, result)
		assert.False(t, result.Success, "should not detect unauth on closed port")
	})

	// Docker
	t.Run("Docker", func(t *testing.T) {
		result := brutus.CheckUnauthAccess(ctx, "127.0.0.1:1", "docker", timeout, brutus.PluginConfig{})
		require.NotNil(t, result)
		assert.False(t, result.Success, "should not detect unauth on closed port")
	})
}
