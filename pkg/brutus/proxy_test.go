package brutus

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyDialFunc_EmptyURL(t *testing.T) {
	fn, err := NewProxyDialFunc("", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn != nil {
		t.Fatal("expected nil function for empty URL")
	}
}

func TestNewProxyDialFunc_InvalidURL(t *testing.T) {
	_, err := NewProxyDialFunc("://bad", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestNewProxyDialFunc_UnsupportedScheme(t *testing.T) {
	_, err := NewProxyDialFunc("http://127.0.0.1:1080", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestNewProxyDialFunc_ValidSOCKS5(t *testing.T) {
	fn, err := NewProxyDialFunc("socks5://127.0.0.1:1080", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn == nil {
		t.Fatal("expected non-nil function for valid SOCKS5 URL")
	}
}

func TestNewProxyDialFunc_ValidSOCKS5h(t *testing.T) {
	fn, err := NewProxyDialFunc("socks5h://127.0.0.1:1080", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn == nil {
		t.Fatal("expected non-nil function for valid socks5h URL")
	}
}

func TestDialWithProxy_EmptyProxy(t *testing.T) {
	// With empty proxy, should fall back to DialWithContext (direct connection).
	// Connect to a non-routable address to verify it at least tries direct.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := DialWithProxy(ctx, "tcp", "192.0.2.1:1", 100*time.Millisecond, "")
	if err == nil {
		t.Fatal("expected connection error to non-routable address")
	}
}

func TestDialWithProxy_InvalidProxy(t *testing.T) {
	ctx := context.Background()
	_, err := DialWithProxy(ctx, "tcp", "127.0.0.1:22", 5*time.Second, "http://127.0.0.1:1080")
	if err == nil {
		t.Fatal("expected error for unsupported proxy scheme")
	}
}

func TestDialWithProxy_UnreachableProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := DialWithProxy(ctx, "tcp", "127.0.0.1:22", 500*time.Millisecond, "socks5://192.0.2.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable proxy")
	}
}

func TestNewHTTPClientWithProxy_EmptyProxy(t *testing.T) {
	client, err := NewHTTPClientWithProxy(5*time.Second, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
}

func TestNewHTTPClientWithProxy_InvalidProxy(t *testing.T) {
	// Invalid proxy should return an error instead of silently falling back.
	// ftp:// is not a supported proxy scheme; must error (no silent fallback).
	_, err := NewHTTPClientWithProxy(5*time.Second, nil, "ftp://bad:1080")
	if err == nil {
		t.Fatal("expected error for unsupported proxy scheme")
	}
}

func TestNewHTTPClientWithProxy_ValidSOCKS5(t *testing.T) {
	client, err := NewHTTPClientWithProxy(5*time.Second, nil, "socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.DialContext == nil {
		t.Fatal("expected DialContext to be set for SOCKS5 proxy")
	}
}

func TestPluginConfig_ProxyURL(t *testing.T) {
	cfg := PluginConfig{ProxyURL: "socks5://127.0.0.1:1080"}
	if cfg.ProxyURL != "socks5://127.0.0.1:1080" {
		t.Errorf("expected proxy URL to be set, got %q", cfg.ProxyURL)
	}
}

func TestPluginConfig_ProxyURL_Empty(t *testing.T) {
	cfg := PluginConfig{}
	if cfg.ProxyURL != "" {
		t.Errorf("expected empty proxy URL, got %q", cfg.ProxyURL)
	}
}

func TestNewHTTPClient_BackwardCompat(t *testing.T) {
	// NewHTTPClient should still work (delegates to NewHTTPClientWithProxy with empty proxy).
	client := NewHTTPClient(5*time.Second, nil)
	if client == nil {
		t.Fatal("expected non-nil client from NewHTTPClient")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
}

// ---------------------------------------------------------------------------
// TestBuildProxyURL — Section A
// ---------------------------------------------------------------------------

func TestBuildProxyURL(t *testing.T) {
	tests := []struct {
		name        string
		proxyURL    string
		proxyUser   string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{
			name:     "bare host:port defaults to http scheme",
			proxyURL: "brd.superproxy.io:33335",
			wantURL:  "http://brd.superproxy.io:33335",
		},
		{
			name:      "bare host:port + proxyUser with password",
			proxyURL:  "brd.superproxy.io:33335",
			proxyUser: "u:p",
			wantURL:   "http://u:p@brd.superproxy.io:33335",
		},
		{
			name:      "proxyUser username-only (no colon) sets userinfo without password",
			proxyURL:  "brd.superproxy.io:33335",
			proxyUser: "u",
			wantURL:   "http://u@brd.superproxy.io:33335",
		},
		{
			name:     "socks5 scheme preserved",
			proxyURL: "socks5://h:1080",
			wantURL:  "socks5://h:1080",
		},
		{
			name:     "https scheme preserved",
			proxyURL: "https://h:8080",
			wantURL:  "https://h:8080",
		},
		{
			name:      "proxyUser overrides embedded userinfo",
			proxyURL:  "http://old:old@h:8080",
			proxyUser: "new:new2",
			wantURL:   "http://new:new2@h:8080",
		},
		{
			name:     "empty proxy and empty user returns empty string, no error",
			proxyURL: "",
			wantURL:  "",
		},
		{
			name:        "empty proxy with non-empty user returns error containing 'requires'",
			proxyURL:    "",
			proxyUser:   "u:p",
			wantErr:     true,
			errContains: "requires",
		},
		{
			name:     "unsupported scheme ftp returns error",
			proxyURL: "ftp://h:1",
			wantErr:  true,
		},
		{
			name:     "whitespace trimmed from proxyURL",
			proxyURL: "  http://h:8080  ",
			wantURL:  "http://h:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildProxyURL(tt.proxyURL, tt.proxyUser)
			if tt.wantErr {
				require.Error(t, err, "expected an error but got none")
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tt.wantURL != "" {
				assert.Equal(t, tt.wantURL, got)
			}
		})
	}
}

// TestBuildProxyURL_BrightDataCredentials verifies the Bright-Data-style table
// entry from the task spec: the returned URL is non-empty and parseable.
// The full round-trip (percent-decoded user/pass) is in TestBuildProxyURL_BrightDataRoundTrip.
func TestBuildProxyURL_BrightDataCredentials(t *testing.T) {
	const (
		user = "brd-customer-hl_e2c7d411-zone-brightdatacenter_proxies"
		pass = "7rgw7v3345ni"
	)
	got, err := BuildProxyURL("http://brd.superproxy.io:33335", user+":"+pass)
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	_, parseErr := (&url.URL{}).Parse(got)
	assert.NoError(t, parseErr, "output URL must be parseable")
}

// TestBuildProxyURL_BrightDataRoundTrip verifies that a realistic Bright Data
// username (containing underscores and hyphens) round-trips through
// BuildProxyURL: parsing the output URL must yield the same user/pass
// (percent-decoded) that were supplied.
func TestBuildProxyURL_BrightDataRoundTrip(t *testing.T) {
	const (
		wantUser = "brd-customer-hl_e2c7d411-zone-brightdatacenter_proxies"
		wantPass = "7rgw7v3345ni"
	)

	result, err := BuildProxyURL("http://brd.superproxy.io:33335", wantUser+":"+wantPass)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	parsed, err := url.Parse(result)
	require.NoError(t, err)
	require.NotNil(t, parsed.User, "expected userinfo in parsed URL")

	gotUser := parsed.User.Username()
	gotPass, _ := parsed.User.Password()
	assert.Equal(t, wantUser, gotUser, "percent-decoded username must match")
	assert.Equal(t, wantPass, gotPass, "percent-decoded password must match")
}

// ---------------------------------------------------------------------------
// TestProxyTransport — Section B
// ---------------------------------------------------------------------------

func TestProxyTransport(t *testing.T) {
	t.Run("http proxy sets Transport.Proxy not DialContext", func(t *testing.T) {
		transport, err := ProxyTransport("http://u:p@h:8080", 5*time.Second, nil)
		require.NoError(t, err)
		require.NotNil(t, transport)
		assert.NotNil(t, transport.Proxy, "expected Proxy to be set for http scheme")
		assert.Nil(t, transport.DialContext, "expected DialContext to be nil for http scheme")

		// Call transport.Proxy with a sample request and assert the returned URL host/user.
		req := httptest.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
		proxyURL, err := transport.Proxy(req)
		require.NoError(t, err)
		require.NotNil(t, proxyURL)
		assert.Equal(t, "h:8080", proxyURL.Host)
		require.NotNil(t, proxyURL.User, "expected userinfo on proxy URL")
		assert.Equal(t, "u", proxyURL.User.Username())
		pass, _ := proxyURL.User.Password()
		assert.Equal(t, "p", pass)
	})

	t.Run("socks5 proxy sets DialContext not Proxy", func(t *testing.T) {
		transport, err := ProxyTransport("socks5://h:1080", 5*time.Second, nil)
		require.NoError(t, err)
		require.NotNil(t, transport)
		assert.NotNil(t, transport.DialContext, "expected DialContext to be set for socks5 scheme")
		assert.Nil(t, transport.Proxy, "expected Proxy to be nil for socks5 scheme")
	})

	t.Run("empty proxy sets neither Proxy nor DialContext", func(t *testing.T) {
		transport, err := ProxyTransport("", 5*time.Second, nil)
		require.NoError(t, err)
		require.NotNil(t, transport)
		assert.Nil(t, transport.Proxy)
		assert.Nil(t, transport.DialContext)
	})

	t.Run("unsupported scheme ftp returns error", func(t *testing.T) {
		_, err := ProxyTransport("ftp://h:1", 5*time.Second, nil)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// TestProxyAuthorization_EndToEnd — Section C
// ---------------------------------------------------------------------------

// TestProxyAuthorization_EndToEnd stands up an httptest server acting as an
// HTTP forward proxy. It verifies that NewHTTPClientWithProxy produces a client
// that automatically injects Proxy-Authorization: Basic <credentials> when the
// proxy URL contains userinfo, for plain-HTTP target requests (which Go sends
// to the proxy in absolute form without CONNECT).
func TestProxyAuthorization_EndToEnd(t *testing.T) {
	const (
		proxyUser = "user"
		proxyPass = "pass"
	)
	// expected Basic auth token: base64("user:pass")
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+proxyPass))

	var gotProxyAuth string

	// Proxy handler: capture Proxy-Authorization, echo 200 with body.
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "proxy-ok")
	}))
	defer proxySrv.Close()

	proxyURL := fmt.Sprintf("http://%s:%s@%s", proxyUser, proxyPass, proxySrv.Listener.Addr().String())
	client, err := NewHTTPClientWithProxy(5*time.Second, nil, proxyURL)
	require.NoError(t, err)

	// Make a GET to a plain-http URL. Go sends it to the proxy in absolute form.
	resp, err := client.Get("http://target.example/path")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, wantBasic, gotProxyAuth,
		"proxy handler must receive Proxy-Authorization: Basic <base64(user:pass)>")
}
