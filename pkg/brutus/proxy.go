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
	"fmt"
	"net/url"
	"strings"
)

// Supported proxy URL schemes.
const (
	proxySchemeHTTP    = "http"
	proxySchemeHTTPS   = "https"
	proxySchemeSOCKS5  = "socks5"
	proxySchemeSOCKS5H = "socks5h"
)

// parseProxyURL parses and validates a proxy URL, accepting the HTTP(S) and
// SOCKS5 schemes. Returning the parsed *url.URL keeps credential handling
// centralized so callers never re-parse.
func parseProxyURL(proxyURL string) (*url.URL, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch u.Scheme {
	case proxySchemeHTTP, proxySchemeHTTPS, proxySchemeSOCKS5, proxySchemeSOCKS5H:
		return u, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (supported: http, https, socks5, socks5h)", u.Scheme)
	}
}

// BuildProxyURL merges a --proxy value with optional --proxy-user credentials
// into a single canonical proxy URL string consumed by the HTTP and SOCKS5
// plumbing (NewHTTPClientWithProxy, ProxyTransport, NewProxyDialFunc).
//
// Behavior mirrors curl: a scheme-less proxy value (a bare host:port such as
// "brd.superproxy.io:33335") defaults to the http scheme. Credentials supplied
// via proxyUser ("user:pass", or "user" for a password-less proxy) take
// precedence over any userinfo already embedded in proxyURL, so the explicit
// flag always wins.
//
// Returns "" when proxyURL is empty. Returns an error when proxyUser is set
// without proxyURL, the scheme is unsupported, or the result has no host.
func BuildProxyURL(proxyURL, proxyUser string) (string, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	proxyUser = strings.TrimSpace(proxyUser)

	if proxyURL == "" {
		if proxyUser != "" {
			return "", fmt.Errorf("--proxy-user requires --proxy")
		}
		return "", nil
	}

	// Default a bare host:port to http, matching curl's --proxy default.
	if !strings.Contains(proxyURL, "://") {
		proxyURL = proxySchemeHTTP + "://" + proxyURL
	}

	u, err := parseProxyURL(proxyURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid proxy URL %q: missing host", u.Redacted())
	}

	if proxyUser != "" {
		if name, pass, found := strings.Cut(proxyUser, ":"); found {
			u.User = url.UserPassword(name, pass)
		} else {
			u.User = url.User(proxyUser)
		}
	}

	return u.String(), nil
}
