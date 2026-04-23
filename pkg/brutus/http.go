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
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
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
