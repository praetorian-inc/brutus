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

// pkg/enum/httpclient.go
package enum

import (
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// defaultUserAgent is a common browser UA to avoid fingerprinting.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// maxResponseBody is the default body read limit (1 MB).
const maxResponseBody int64 = 1 << 20

// uaTransport wraps an http.RoundTripper to inject a default User-Agent.
type uaTransport struct {
	base http.RoundTripper
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		r2 := req.Clone(req.Context())
		r2.Header.Set("User-Agent", defaultUserAgent)
		return t.base.RoundTrip(r2)
	}
	return t.base.RoundTrip(req)
}

// NewEnumHTTPClient returns an HTTP client with safe defaults for enum plugins:
//   - No redirect following (returns last response)
//   - Default User-Agent header
//   - Specified timeout
//
// It never routes through a proxy; use NewEnumHTTPClientWithProxy to honor the
// --proxy flag.
func NewEnumHTTPClient(timeout time.Duration) *http.Client {
	// Empty proxy never errors.
	client, _ := NewEnumHTTPClientWithProxy(timeout, "")
	return client
}

// NewEnumHTTPClientWithProxy returns an enum HTTP client (same safe defaults as
// NewEnumHTTPClient) that routes requests through proxyURL when it is non-empty.
// Supports http/https proxies (with authenticated credentials via URL userinfo)
// and socks5/socks5h. Returns an error if the proxy URL is invalid or uses an
// unsupported scheme.
func NewEnumHTTPClientWithProxy(timeout time.Duration, proxyURL string) (*http.Client, error) {
	transport, err := brutus.ProxyTransport(proxyURL, timeout, nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &uaTransport{base: transport},
	}, nil
}

// ReadResponseBody reads a response body with a size limit to prevent OOM from hostile endpoints.
// If limit is 0, maxResponseBody (1 MB) is used.
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxResponseBody
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
