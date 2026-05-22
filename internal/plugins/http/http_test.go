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

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		p := &Plugin{UseHTTPS: false}
		assert.Equal(t, "http", p.Name())
	})

	t.Run("HTTPS", func(t *testing.T) {
		p := &Plugin{UseHTTPS: true}
		assert.Equal(t, "https", p.Name())
	})
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Create test server with Basic Auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Test"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome"))
	}))
	defer server.Close()

	// Extract host:port from server URL
	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "admin", "secret", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.Equal(t, "http", result.Protocol)
	assert.Equal(t, target, result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "secret", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Create test server with Basic Auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Test"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "admin", "wrongpassword", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.Equal(t, "http", result.Protocol)
	assert.Equal(t, target, result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_BannerCapture_Grafana(t *testing.T) {
	// Simulate Grafana login page
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Grafana")
		w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><head><title>Grafana</title></head><body>Grafana Login</body></html>`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	// Test without auth to capture banner
	result := p.Test(ctx, target, "", "", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success) // No auth provided

	// Check banner captured
	assert.Contains(t, result.Banner, "Server: Grafana")
	assert.Contains(t, result.Banner, "WWW-Authenticate: Basic realm=\"Grafana\"")
	assert.Contains(t, result.Banner, "App-Identifier: Grafana")
}

func TestPlugin_Test_BannerCapture_Jenkins(t *testing.T) {
	// Simulate Jenkins login page
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Jetty")
		w.Header().Set("X-Powered-By", "Jenkins")
		w.Header().Set("WWW-Authenticate", `Basic realm="Jenkins"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><head><title>Jenkins</title></head><body>Authentication required</body></html>`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "", "", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.Contains(t, result.Banner, "X-Powered-By: Jenkins")
	assert.Contains(t, result.Banner, "App-Identifier: Jenkins")
}

func TestPlugin_Test_BannerCapture_MultipleApps(t *testing.T) {
	// Simulate response mentioning multiple technologies
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html>Prometheus metrics - Grafana dashboard</html>`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "", "", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.Contains(t, result.Banner, "App-Identifier:")
	// Should detect both Prometheus and Grafana
	assert.Contains(t, result.Banner, "Prometheus")
	assert.Contains(t, result.Banner, "Grafana")
}

func TestPlugin_Test_NoBasicAuth_FalsePositive(t *testing.T) {
	// Server that returns 200 for all requests regardless of credentials.
	// This simulates websites like ginandjuice.shop that don't use Basic Auth.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Welcome to the site</body></html>`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	// Even though the server returns 200, these should NOT be reported as valid
	// because the server doesn't actually require Basic Auth.
	result := p.Test(ctx, target, "admin", "changeme", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success, "should not report success when server doesn't require Basic Auth")
	assert.Nil(t, result.Error, "should be auth failure, not connection error")
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "admin", "password", 2*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.Equal(t, "http", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, target, "admin", "password", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:8080", "admin", "password", 500*time.Millisecond, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ForbiddenResponse(t *testing.T) {
	// Server returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	p := &Plugin{Path: "/", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "admin", "password", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // 403 is auth failure, not connection error
}

func TestPlugin_Test_CustomPath(t *testing.T) {
	// Server that only authenticates on /admin path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Admin Panel"))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	// Test with custom path
	p := &Plugin{Path: "/admin", UseHTTPS: false}
	ctx := context.Background()

	result := p.Test(ctx, target, "admin", "secret", 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestExtractAppIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "Grafana",
			body:     `<html><title>Grafana</title><body>Welcome to grafana-app</body></html>`,
			expected: []string{"Grafana"},
		},
		{
			name:     "Jenkins",
			body:     `<html><title>Jenkins</title><body>hudson dashboard</body></html>`,
			expected: []string{"Jenkins"},
		},
		{
			name:     "Multiple apps",
			body:     `Prometheus metrics with Grafana dashboard`,
			expected: []string{"Grafana", "Prometheus"},
		},
		{
			name:     "No apps detected",
			body:     `<html><body>Hello World</body></html>`,
			expected: []string{},
		},
		{
			name:     "Case insensitive",
			body:     `GRAFANA JENKINS PROMETHEUS`,
			expected: []string{"Grafana", "Jenkins", "Prometheus"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAppIdentifiers(tt.body)
			for _, exp := range tt.expected {
				assert.Contains(t, result, exp)
			}
			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			}
		})
	}
}

func TestBuildURL(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *Plugin
		target   string
		expected string
	}{
		{
			name:     "HTTP with port",
			plugin:   &Plugin{Path: "/", UseHTTPS: false},
			target:   "localhost:8080",
			expected: "http://localhost:8080/",
		},
		{
			name:     "HTTPS with port",
			plugin:   &Plugin{Path: "/", UseHTTPS: true},
			target:   "localhost:443",
			expected: "https://localhost:443/",
		},
		{
			name:     "Custom path",
			plugin:   &Plugin{Path: "/admin/login", UseHTTPS: false},
			target:   "example.com:8080",
			expected: "http://example.com:8080/admin/login",
		},
		{
			name:     "Default path when empty",
			plugin:   &Plugin{Path: "", UseHTTPS: false},
			target:   "localhost:80",
			expected: "http://localhost:80/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.plugin.buildURL(tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}
