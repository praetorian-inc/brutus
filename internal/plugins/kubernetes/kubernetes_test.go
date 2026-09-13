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

package kubernetes

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

func stripScheme(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	return url
}

func TestName(t *testing.T) {
	c := &Checker{}
	assert.Equal(t, "kubernetes", c.Name())
}

func TestRegistry_GetUnauthChecker(t *testing.T) {
	checker, err := brutus.GetUnauthChecker("kubernetes")
	require.NoError(t, err)
	require.NotNil(t, checker)
	assert.Equal(t, "kubernetes", checker.Name())
}

func TestCheckUnauth_AnonymousAPI(t *testing.T) {
	versionBody := `{"major":"1","minor":"29","gitVersion":"v1.29.0"}`
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/namespaces":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"NamespaceList"}`))
		case "/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(versionBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c := &Checker{}
	result := c.CheckUnauth(context.Background(), stripScheme(server.URL), 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Contains(t, result.Banner, "[CRITICAL] Kubernetes anonymous access enabled")
	assert.Contains(t, result.Banner, versionBody)
	assert.Contains(t, paths, "/api/v1/namespaces")
	assert.Contains(t, paths, "/version")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheckUnauth_SecuredAPI(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
		{"404 NotFound", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			c := &Checker{}
			result := c.CheckUnauth(context.Background(), stripScheme(server.URL), 5*time.Second, brutus.PluginConfig{})

			require.NotNil(t, result)
			assert.False(t, result.Success)
			assert.Empty(t, result.Banner)
		})
	}
}

func TestCheckUnauth_Kubelet(t *testing.T) {
	var requestedPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"PodList"}`))
	}))
	defer server.Close()

	host, port, err := net.SplitHostPort(stripScheme(server.URL))
	require.NoError(t, err)

	c := &Checker{}
	result := brutus.NewResult("kubernetes", "kubelet", "(unauthenticated)", "")
	out := c.checkKubelet(context.Background(), server.Client(), "https", host, port, result)

	require.NotNil(t, out)
	assert.True(t, out.Success)
	assert.Contains(t, out.Banner, "Kubelet API accessible without authentication")
	assert.Equal(t, "/pods", requestedPath)
}

func TestCheckUnauth_KubeletDenied(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	host, port, err := net.SplitHostPort(stripScheme(server.URL))
	require.NoError(t, err)

	c := &Checker{}
	result := brutus.NewResult("kubernetes", "kubelet", "(unauthenticated)", "")
	out := c.checkKubelet(context.Background(), server.Client(), "https", host, port, result)

	require.NotNil(t, out)
	assert.False(t, out.Success)
	assert.Empty(t, out.Banner)
}

func TestCheckUnauth_CancelledContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &Checker{}
	result := c.CheckUnauth(ctx, stripScheme(server.URL), 5*time.Second, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestCheckUnauth_InvalidProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"NamespaceList"}`))
	}))
	defer server.Close()

	c := &Checker{}
	result := c.CheckUnauth(context.Background(), stripScheme(server.URL), 5*time.Second, brutus.PluginConfig{
		ProxyURL: "ftp://127.0.0.1:9",
	})

	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestCheckUnauth_UnbracketedIPv6(t *testing.T) {
	c := &Checker{}
	result := c.CheckUnauth(context.Background(), "::1", 200*time.Millisecond, brutus.PluginConfig{})

	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Equal(t, "kubernetes", result.Protocol)
	assert.Equal(t, "::1", result.Target)
}
