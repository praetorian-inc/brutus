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

package brutus

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectHTTPAuthType_ClosesIdleConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "Test page")
	}))
	defer server.Close()

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	goroutinesBefore := runtime.NumGoroutine()

	target := server.URL[7:] // Remove "http://" prefix
	for i := 0; i < 50; i++ {
		DetectHTTPAuthType(target, false, 5*time.Second, "skip")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	goroutinesAfter := runtime.NumGoroutine()
	goroutineGrowth := goroutinesAfter - goroutinesBefore

	require.Less(t, goroutineGrowth, 20,
		"Expected goroutine growth < 20, got %d (before: %d, after: %d). "+
			"Transport goroutines are leaking - CloseIdleConnections() not called",
		goroutineGrowth, goroutinesBefore, goroutinesAfter)
}

func TestDetectHTTPAuthType_BasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseHeader map[string]string
		expectedAuth   string
	}{
		{
			name:           "WWW-Authenticate header present",
			responseStatus: http.StatusUnauthorized,
			responseHeader: map[string]string{"WWW-Authenticate": "Basic realm=\"test\""},
			expectedAuth:   "basic",
		},
		{
			name:           "401 without WWW-Authenticate",
			responseStatus: http.StatusUnauthorized,
			responseHeader: map[string]string{},
			expectedAuth:   "basic",
		},
		{
			name:           "Form-based (200 OK)",
			responseStatus: http.StatusOK,
			responseHeader: map[string]string{},
			expectedAuth:   "form",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.responseHeader {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.responseStatus)
			}))
			defer server.Close()

			target := server.URL[7:] // Remove "http://" prefix
			authType, _ := DetectHTTPAuthType(target, false, 5*time.Second, "skip")

			require.Equal(t, tt.expectedAuth, authType)
		})
	}
}

func TestHTTPBasicAuthProbe_Run(t *testing.T) {
	t.Run("success (200)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodGet,
			Path:         "/",
			SuccessCodes: []int{http.StatusOK},
		}

		result := probe.Run(context.Background(), target, "user", "pass", 5*time.Second, PluginConfig{})

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
		assert.Equal(t, "testsvc", result.Protocol)
		assert.Equal(t, target, result.Target)
		assert.Greater(t, result.Duration, time.Duration(0))
	})

	t.Run("auth failure (401)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodGet,
			Path:         "/",
			SuccessCodes: []int{http.StatusOK},
		}

		result := probe.Run(context.Background(), target, "user", "pass", 5*time.Second, PluginConfig{})

		assert.False(t, result.Success)
		assert.NoError(t, result.Error)
	})

	t.Run("unexpected status (500)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodGet,
			Path:         "/",
			SuccessCodes: []int{http.StatusOK},
		}

		result := probe.Run(context.Background(), target, "user", "pass", 5*time.Second, PluginConfig{})

		assert.False(t, result.Success)
		require.Error(t, result.Error)
		assert.Contains(t, result.Error.Error(), "connection error")
	})

	t.Run("success via 204 (multiple success codes)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodPost,
			Path:         "/",
			SuccessCodes: []int{http.StatusOK, http.StatusNoContent},
		}

		result := probe.Run(context.Background(), target, "user", "pass", 5*time.Second, PluginConfig{})

		assert.True(t, result.Success)
		assert.NoError(t, result.Error)
	})

	t.Run("method and path propagation", func(t *testing.T) {
		var gotMethod, gotPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodPost,
			Path:         "/api/v2/signin",
			SuccessCodes: []int{http.StatusOK},
		}

		_ = probe.Run(context.Background(), target, "user", "pass", 5*time.Second, PluginConfig{})

		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "/api/v2/signin", gotPath)
	})

	t.Run("basic auth credentials sent", func(t *testing.T) {
		var gotUser, gotPass string
		var gotOK bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, gotOK = r.BasicAuth()
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)

		target := strings.TrimPrefix(server.URL, "http://")
		probe := HTTPBasicAuthProbe{
			Service:      "testsvc",
			Method:       http.MethodGet,
			Path:         "/",
			SuccessCodes: []int{http.StatusOK},
		}

		_ = probe.Run(context.Background(), target, "myuser", "mypass", 5*time.Second, PluginConfig{})

		require.True(t, gotOK)
		assert.Equal(t, "myuser", gotUser)
		assert.Equal(t, "mypass", gotPass)
	})
}
