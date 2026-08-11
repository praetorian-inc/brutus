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

package docker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// stripScheme strips the http:// or https:// prefix from a server URL,
// returning a bare host:port target string as CheckUnauth expects.
func stripScheme(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	return url
}

func TestName(t *testing.T) {
	c := &Checker{}
	assert.Equal(t, "docker", c.Name())
}

func TestRegistry_GetUnauthChecker(t *testing.T) {
	checker, err := brutus.GetUnauthChecker("docker")
	require.NoError(t, err)
	require.NotNil(t, checker)
	assert.Equal(t, "docker", checker.Name())
}

func TestCheckUnauth_ExposedDaemon(t *testing.T) {
	versionBody := `{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`

	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(versionBody))
	}))
	defer server.Close()

	c := &Checker{}
	ctx := context.Background()
	target := stripScheme(server.URL)

	result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Contains(t, result.Banner, "[CRITICAL] Docker daemon API exposed without authentication")
	assert.Contains(t, result.Banner, versionBody)
	assert.Equal(t, "/version", requestedPath)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheckUnauth_SecuredDaemon(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
		{"404 NotFound", http.StatusNotFound},
		{"500 InternalServerError", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			c := &Checker{}
			ctx := context.Background()
			target := stripScheme(server.URL)

			result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Empty(t, result.Banner)
		})
	}
}

func TestCheckUnauth_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// no body written
	}))
	defer server.Close()

	c := &Checker{}
	ctx := context.Background()
	target := stripScheme(server.URL)

	result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.NotContains(t, result.Banner, "Version info:")
}

func TestCheckUnauth_OversizedBodyCapped(t *testing.T) {
	oversized := strings.Repeat("A", 4096)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(oversized))
	}))
	defer server.Close()

	c := &Checker{}
	ctx := context.Background()
	target := stripScheme(server.URL)

	result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success)

	const prefix = "\nVersion info: "
	idx := strings.Index(result.Banner, prefix)
	require.NotEqual(t, -1, idx, "banner should contain version info section")
	capturedPayload := result.Banner[idx+len(prefix):]
	assert.Len(t, capturedPayload, 1024, "captured body must be capped at 1024 bytes via io.LimitReader")
}

func TestCheckUnauth_Unreachable(t *testing.T) {
	// Bind a listener then immediately close it to obtain a closed port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	c := &Checker{}
	ctx := context.Background()

	result := c.CheckUnauth(ctx, addr, 2*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
	// NOTE: This documents CURRENT behavior, which diverges from the Plugin
	// contract described in pkg/brutus/brutus.go (connection errors are
	// supposed to set Error != nil). CheckUnauth's client.Do error path
	// returns the zero-value result unchanged, leaving Error nil. As a
	// result, an unreachable host is currently indistinguishable from a
	// secured daemon that returned a non-200 status.
	assert.Nil(t, result.Error)
}

func TestCheckUnauth_TLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"24.0.7"}`))
	}))
	defer server.Close()

	c := &Checker{}
	ctx := context.Background()
	target := stripScheme(server.URL)

	result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{TLSMode: "skip-verify"})

	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Contains(t, result.Banner, "[CRITICAL]")
}

func TestCheckUnauth_InvalidProxy(t *testing.T) {
	// Live server that WOULD yield Success=true if the proxy error early-return
	// were skipped, proving the assertion below is actually exercising the
	// proxy-error path rather than an unrelated failure.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"24.0.7"}`))
	}))
	defer server.Close()

	c := &Checker{}
	ctx := context.Background()
	target := stripScheme(server.URL)

	// "ftp" is not one of the schemes parseProxyURL (pkg/brutus/proxy.go)
	// accepts (http, https, socks5, socks5h), so ProxyTransport returns an
	// "unsupported proxy scheme" error before any request is attempted.
	result := c.CheckUnauth(ctx, target, 5*time.Second, brutus.PluginConfig{ProxyURL: "ftp://127.0.0.1:9"})

	require.NotNil(t, result)
	// Success would be true here if the client-construction error early return
	// were removed, since the live server above always responds 200.
	assert.False(t, result.Success)
	// NOTE: Same contract divergence documented in TestCheckUnauth_Unreachable:
	// a proxy misconfiguration is silently reported as "no unauthenticated
	// access found" (Error remains nil) rather than surfacing as an error.
	assert.Nil(t, result.Error)
}
