package brutus

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ReadLine reads a newline-terminated line from a bufio.Reader and trims whitespace.
// This is a shared helper for text-protocol plugins (FTP, POP3).
func ReadLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// DialWithContext dials a network address with a timeout and context support.
// This is a shared helper for plugins that make raw TCP connections (ssh, ftp, pop3, telnet).
func DialWithContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	return dialer.DialContext(ctx, network, address)
}

// DialWithProxy dials a network address, routing through a SOCKS5 proxy when proxyURL
// is non-empty. Falls back to a direct connection when no proxy is configured.
// Supported proxy schemes: socks5://, socks5h:// (with optional user:pass authentication).
func DialWithProxy(ctx context.Context, network, address string, timeout time.Duration, proxyURL string) (net.Conn, error) {
	if proxyURL == "" {
		return DialWithContext(ctx, network, address, timeout)
	}

	dialFunc, err := NewProxyDialFunc(proxyURL, timeout)
	if err != nil {
		return nil, err
	}
	return dialFunc(ctx, network, address)
}

// ProxyDialFunc is a context-aware dial function that can be used with net.Dialer
// or http.Transport.DialContext.
type ProxyDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewProxyDialFunc returns a context-aware dial function that routes raw TCP
// connections through the given SOCKS5 proxy. Returns nil and no error if
// proxyURL is empty. Only socks5/socks5h are supported here; HTTP(S) proxies
// cannot tunnel arbitrary TCP and are rejected (use them via the HTTP client
// path instead).
func NewProxyDialFunc(proxyURL string, timeout time.Duration) (ProxyDialFunc, error) {
	if proxyURL == "" {
		return nil, nil
	}

	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case proxySchemeSOCKS5, proxySchemeSOCKS5H:
		return socksDialFunc(u, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q for raw TCP dialing (supported: socks5, socks5h)", u.Scheme)
	}
}

// socksDialFunc builds a context-aware dial function from an already-parsed
// socks5/socks5h proxy URL.
func socksDialFunc(u *url.URL, timeout time.Duration) (ProxyDialFunc, error) {
	baseDialer := &net.Dialer{Timeout: timeout}

	socksDialer, err := proxy.FromURL(u, baseDialer)
	if err != nil {
		return nil, fmt.Errorf("creating SOCKS5 dialer from %q: %w", u.Redacted(), err)
	}

	// Prefer DialContext for proper cancellation support.
	if cd, ok := socksDialer.(proxy.ContextDialer); ok {
		return cd.DialContext, nil
	}

	// Fallback: wrap Dial without context awareness.
	return func(_ context.Context, network, address string) (net.Conn, error) {
		return socksDialer.Dial(network, address)
	}, nil
}
