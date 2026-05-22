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

package elasticsearch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "elasticsearch", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no Elasticsearch server available
	// In real tests, use Docker container with known credentials
	t.Skip("Integration test - requires Elasticsearch server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:9200", "elastic", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "elasticsearch", result.Protocol)
	assert.Equal(t, "localhost:9200", result.Target)
	assert.Equal(t, "elastic", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no Elasticsearch server available
	t.Skip("Integration test - requires Elasticsearch server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:9200", "elastic", "wrongpassword", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "elasticsearch", result.Protocol)
	assert.Equal(t, "localhost:9200", result.Target)
	assert.Equal(t, "elastic", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure (401) returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "elastic", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "elasticsearch", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires Elasticsearch server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, "localhost:9200", "elastic", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:9200", "elastic", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

// =============================================================================
// CheckUnauth tests (using httptest for mock HTTP servers)
// =============================================================================

func TestCheckUnauth_OpenAccess(t *testing.T) {
	// Simulate Elasticsearch with security disabled (200 OK without auth)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"), "CheckUnauth should NOT send auth header")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"node-1","cluster_name":"test","version":{"number":"8.12.0"}}`))
	}))
	defer server.Close()

	p := &Plugin{}
	ctx := context.Background()
	// Strip http:// and use the server's host:port directly
	target := server.Listener.Addr().String()

	result := p.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success, "should detect unauthenticated access")
	assert.Equal(t, "(unauthenticated)", result.Username)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "Elasticsearch accessible without authentication")
	assert.Contains(t, result.Banner, "node-1") // cluster info should be included
}

func TestCheckUnauth_RequiresAuth(t *testing.T) {
	// Simulate Elasticsearch with security enabled (401 Unauthorized)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := &Plugin{}
	ctx := context.Background()
	target := server.Listener.Addr().String()

	result := p.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success, "should NOT detect unauth access when 401 returned")
	assert.Empty(t, result.Banner)
}

func TestCheckUnauth_ServerError(t *testing.T) {
	// Simulate Elasticsearch returning 500 (server error, not open access)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := &Plugin{}
	ctx := context.Background()
	target := server.Listener.Addr().String()

	result := p.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success, "non-200 status should not be detected as open")
}

func TestCheckUnauth_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Target that is not reachable
	result := p.CheckUnauth(ctx, "127.0.0.1:1", 1*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
}
