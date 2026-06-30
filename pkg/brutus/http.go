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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NewHTTPClient creates an *http.Client with the given timeout and TLS config.
// This is a shared helper for plugins that make HTTP requests (elasticsearch, couchdb, influxdb, http).
func NewHTTPClient(timeout time.Duration, tlsConfig *tls.Config) *http.Client {
	// Empty proxy never errors.
	client, _ := NewHTTPClientWithProxy(timeout, tlsConfig, "")
	return client
}

// NewHTTPClientWithProxy creates an *http.Client that routes requests through a
// proxy when proxyURL is non-empty. Supports socks5/socks5h (raw TCP dialing)
// and http/https (HTTP CONNECT / absolute-form, with Proxy-Authorization
// derived from URL userinfo). Returns an error if the proxy URL is invalid or
// uses an unsupported scheme, rather than silently falling back to a direct
// connection.
func NewHTTPClientWithProxy(timeout time.Duration, tlsConfig *tls.Config, proxyURL string) (*http.Client, error) {
	transport, err := ProxyTransport(proxyURL, timeout, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}

// ProxyTransport builds an *http.Transport configured to route requests through
// proxyURL. An empty proxyURL yields a direct transport. socks5/socks5h proxies
// are wired via DialContext; http/https proxies via Transport.Proxy (Go injects
// Proxy-Authorization from the URL userinfo automatically). tlsConfig may be nil.
func ProxyTransport(proxyURL string, timeout time.Duration, tlsConfig *tls.Config) (*http.Transport, error) {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if proxyURL == "" {
		return transport, nil
	}

	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case proxySchemeSOCKS5, proxySchemeSOCKS5H:
		dialFunc, err := socksDialFunc(u, timeout)
		if err != nil {
			return nil, fmt.Errorf("configuring proxy: %w", err)
		}
		transport.DialContext = dialFunc
	case proxySchemeHTTP, proxySchemeHTTPS:
		transport.Proxy = http.ProxyURL(u)
	}

	return transport, nil
}

// SchemeFromTLSMode returns "https" if TLS is enabled, "http" otherwise.
// This is a shared helper for plugins that build URLs based on TLS mode.
func SchemeFromTLSMode(tlsMode string) string {
	if tlsMode == "verify" || tlsMode == "skip-verify" {
		return "https"
	}
	return "http"
}

// DetectHTTPAuthType probes an HTTP target to determine the authentication type.
// Returns auth type ("basic", "form", or "" on error) and the banner text
// containing response headers and body for LLM analysis.
func DetectHTTPAuthType(target string, useHTTPS bool, timeout time.Duration, tlsMode string) (authType, banner string) {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, target)

	client := NewHTTPClient(timeout, BuildTLSConfig(tlsMode))
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		return "", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer func() { _ = resp.Body.Close() }()

	// Build banner from response headers and body
	var bannerBuilder strings.Builder
	fmt.Fprintf(&bannerBuilder, "HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)

	for _, header := range []string{"Server", "WWW-Authenticate", "X-Powered-By", "X-Server", "X-AspNet-Version"} {
		if val := resp.Header.Get(header); val != "" {
			fmt.Fprintf(&bannerBuilder, "%s: %s\n", header, val)
		}
	}

	body := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, body)
	if n > 0 {
		bannerBuilder.WriteString("\n")
		bannerBuilder.Write(body[:n])
	}

	banner = bannerBuilder.String()

	if authHeader := resp.Header.Get("WWW-Authenticate"); authHeader != "" {
		return "basic", banner
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "basic", banner
	}

	return "form", banner
}
