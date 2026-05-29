package brutus

import (
	"context"
	"net/http"
	"testing"
	"time"
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
	client := NewHTTPClientWithProxy(5*time.Second, nil, "")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
}

func TestNewHTTPClientWithProxy_InvalidProxy(t *testing.T) {
	// Invalid proxy is silently ignored — client should still be returned.
	client := NewHTTPClientWithProxy(5*time.Second, nil, "http://bad:1080")
	if client == nil {
		t.Fatal("expected non-nil client even with invalid proxy")
	}
}

func TestNewHTTPClientWithProxy_ValidSOCKS5(t *testing.T) {
	client := NewHTTPClientWithProxy(5*time.Second, nil, "socks5://127.0.0.1:1080")
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
