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

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestRouteHTTP_BasicKeepsProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	proto, creds := RouteHTTP(context.Background(), mustHost(t, srv.URL), "http", time.Second, "disable", "", nil)
	assert.Equal(t, "http", proto)
	assert.Nil(t, creds)
}

func TestRouteHTTP_FormSwitchesToBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<form><input type="password"></form>`))
	}))
	t.Cleanup(srv.Close)

	proto, creds := RouteHTTP(context.Background(), mustHost(t, srv.URL), "http", time.Second, "disable", "", nil)
	assert.Equal(t, "browser", proto)
	assert.Nil(t, creds)
}

func TestRouteHTTP_ProbeFailureKeepsProtocol(t *testing.T) {
	proto, creds := RouteHTTP(context.Background(), "127.0.0.1:1", "https", 200*time.Millisecond, "disable", "", nil)
	assert.Equal(t, "https", proto, "failed detection must not route to browser")
	assert.Nil(t, creds)
}

func TestResearchBrowserCredentials_DisabledLLM(t *testing.T) {
	creds, plugin, err := ResearchBrowserCredentials(context.Background(), "example", BrowserConfig{})
	require.NoError(t, err)
	assert.Nil(t, creds)
	assert.Nil(t, plugin)

	creds, plugin, err = ResearchBrowserCredentials(context.Background(), "example", BrowserConfig{
		LLMConfig: &brutus.LLMConfig{Enabled: false},
	})
	require.NoError(t, err)
	assert.Nil(t, creds)
	assert.Nil(t, plugin)
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Host
}
