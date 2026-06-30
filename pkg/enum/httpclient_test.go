// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enum

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestNewEnumHTTPClientWithProxy — Section D
// ---------------------------------------------------------------------------

func TestNewEnumHTTPClientWithProxy_EmptyProxy(t *testing.T) {
	client, err := NewEnumHTTPClientWithProxy(5*time.Second, "")
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNewEnumHTTPClientWithProxy_UnsupportedScheme(t *testing.T) {
	_, err := NewEnumHTTPClientWithProxy(5*time.Second, "ftp://h:21")
	require.Error(t, err, "unsupported scheme ftp must return error")
}

// TestNewEnumHTTPClientWithProxy_EndToEnd stands up an httptest forward proxy
// that captures request headers. It asserts:
//  1. Proxy-Authorization: Basic <base64("user:pass")> is injected automatically.
//  2. The default User-Agent (Mozilla/5.0 ... Chrome/120...) is still present,
//     proving the uaTransport wrapper survives the proxied transport.
func TestNewEnumHTTPClientWithProxy_EndToEnd(t *testing.T) {
	const (
		proxyUser = "user"
		proxyPass = "pass"
	)
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))

	var (
		gotProxyAuth string
		gotUserAgent string
	)

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		gotUserAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "proxy-ok")
	}))
	defer proxySrv.Close()

	proxyURL := fmt.Sprintf("http://%s:%s@%s", proxyUser, proxyPass, proxySrv.Listener.Addr().String())
	client, err := NewEnumHTTPClientWithProxy(5*time.Second, proxyURL)
	require.NoError(t, err)

	// Plain-http target — Go sends it to the proxy in absolute form.
	resp, err := client.Get("http://target.example/path")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Proxy-Authorization must be present with correct Basic credentials.
	assert.Equal(t, wantBasic, gotProxyAuth,
		"Proxy-Authorization Basic header must match base64(user:pass)")

	// Default User-Agent must be injected by the uaTransport wrapper.
	assert.Contains(t, gotUserAgent, "Chrome/120",
		"default User-Agent must contain Chrome/120 (injected by uaTransport)")
	assert.Contains(t, gotUserAgent, "Mozilla/5.0",
		"default User-Agent must contain Mozilla/5.0 (injected by uaTransport)")
}
