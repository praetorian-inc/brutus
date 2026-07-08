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

// Package github provides GitHub account enumeration by email address. It is a
// Go port of GhEmailBrute with two distinct capabilities:
//
//   - Existence (unauthenticated): the github.com/join sign-up page exposes an
//     email_validity_checks endpoint. POSTing an email there returns HTTP 422
//     when the address is already in use (an account exists) and HTTP 200 when
//     it is available (no account). No token or sign-in is required.
//
//   - Username reveal (authenticated): given a GitHub PAT with repo+delete_repo
//     scope, a throwaway private repo is created and one commit per target email
//     is pushed with that email as the commit author/committer. GitHub resolves
//     each commit's author.login from the email even when the account has email
//     privacy enabled, mapping email -> login. The repo is ALWAYS deleted after.
//
// The existence path mirrors the concurrency model of the google enumerator
// (errgroup + rate.Limiter + jitter + serialized result callback). The reveal
// path is sequential by design (all commits target one branch). The PAT is
// never logged.
//
// Source is split across cohesive files in this package:
//   - github.go   — package doc, Result, Enumerator, NewEnumerator, shared helpers
//   - existence.go — Enumerate/EnumerateWith + session/CSRF/validity helpers
//   - reveal.go    — Reveal + repo create/push/list/delete + apiRequest
package github

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Result is the outcome of checking (and optionally revealing) a single email.
// Username is populated only by Reveal and only when GitHub linked the commit's
// author email to an account login. Email and Username are server-/user-derived
// and are NOT sanitized here; sanitization happens at the output layer.
type Result struct {
	Email    string
	Exists   bool
	Username string
	Error    error
}

const (
	webBaseURLDefault       = "https://github.com"
	apiBaseURLDefault       = "https://api.github.com"
	settleDelayDefault      = 10 * time.Second
	validityCheckPath       = "/email_validity_checks"
	joinPath                = "/join"
	maxRateLimitRetries     = 5
	rateLimitBackoff        = 2 * time.Second
	rotatingProxyBackoff    = 100 * time.Millisecond
	rotatingProxyMaxRetries = 15
	defaultBranchDefault    = "main"
	// commitContent is a tiny constant base64 blob ("Haxor"), matching the
	// reference implementation's per-commit file content.
	commitContent = "SGF4b3I="
)

// Enumerator performs GitHub account enumeration. The existence path is safe for
// concurrent use; Reveal is sequential.
type Enumerator struct {
	// httpClient is used by the unauthenticated existence flow. It intentionally
	// FOLLOWS redirects: github.com/join 302-redirects to github.com/signup, and
	// the CSRF authenticity_token (inside <auto-check src="/email_validity_checks">)
	// only exists on the final /signup page. This flow carries no token, so
	// following redirects is safe.
	httpClient *http.Client
	// apiClient is used by the authenticated reveal flow's API calls, which carry
	// "Authorization: Bearer <PAT>". It is a clone of httpClient that does NOT
	// follow redirects (PAT-leak protection): a subdomain-match redirect, notably
	// under the untrusted --proxy/MITM path this tool supports, could otherwise
	// forward the PAT to an attacker-controlled host. The proxy transport is
	// shared with httpClient. Mirrors pkg/enum/google/google.go.
	apiClient *http.Client
	token     string

	// existenceBackoff / existenceMaxRetries control 429 retry pacing on the
	// unauthenticated, IP-rate-limited existence endpoint. With a rotating proxy
	// (--rotating-proxy) each retry uses a fresh exit IP, so a short backoff and
	// higher ceiling are used instead of the conservative defaults.
	existenceBackoff    time.Duration
	existenceMaxRetries int

	// Base URLs default to the real GitHub hosts and are overridable by tests.
	webBaseURL string
	apiBaseURL string

	// settleDelay is how long Reveal waits after pushing commits before listing
	// them, giving GitHub time to resolve author logins. Overridable by tests.
	settleDelay time.Duration

	// sleep waits for d or until ctx is canceled; overridable by tests to avoid
	// real delays. newName generates a random hex name for repos and files;
	// overridable by tests for determinism.
	sleep   func(ctx context.Context, d time.Duration) error
	newName func() string
}

// session holds the read-only state established once before the worker pool:
// the CSRF authenticity token parsed from the join page and the Cookie header
// built from the join response's Set-Cookie values. It is shared across workers.
type session struct {
	csrfToken    string
	cookieHeader string
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewEnumerator builds an Enumerator. The HTTP client is built via
// brutus.NewHTTPClientWithProxy so the SOCKS5 --proxy flag works. token may be
// empty (existence-only mode); Reveal requires a non-empty token. When
// rotatingProxy is true, the existence path uses a short 429 backoff and a
// higher retry ceiling, since each retry egresses from a fresh exit IP; this
// does not affect the token-rate-limited reveal path.
func NewEnumerator(proxyURL string, timeout time.Duration, token string, rotatingProxy bool) (*Enumerator, error) {
	httpClient, err := brutus.NewHTTPClientWithProxy(timeout, nil, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("github enum: configuring HTTP client: %w", err)
	}

	existenceBackoff := rateLimitBackoff
	existenceMaxRetries := maxRateLimitRetries
	if rotatingProxy {
		existenceBackoff = rotatingProxyBackoff
		existenceMaxRetries = rotatingProxyMaxRetries
	}

	// httpClient FOLLOWS redirects (the default): the existence flow's join-page
	// GET hits github.com/join, which 302-redirects to github.com/signup where the
	// CSRF authenticity_token lives. That flow carries no token, so following the
	// redirect is safe and required.
	//
	// apiClient is a clone of httpClient that does NOT follow redirects. The reveal
	// flow's API calls carry "Authorization: Bearer <PAT>", and a subdomain-match
	// redirect (notably under the untrusted --proxy/MITM path) could forward the
	// PAT to an attacker-controlled host. Refuse redirects there (PAT-leak
	// protection) while keeping the shared proxy transport. Mirrors
	// pkg/enum/google/google.go.
	apiClient := *httpClient
	apiClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Enumerator{
		httpClient:          httpClient,
		apiClient:           &apiClient,
		token:               token,
		existenceBackoff:    existenceBackoff,
		existenceMaxRetries: existenceMaxRetries,
		webBaseURL:          webBaseURLDefault,
		apiBaseURL:          apiBaseURLDefault,
		settleDelay:         settleDelayDefault,
		sleep:               sleepCtx,
		newName:             randomHexName,
	}, nil
}

// ---------------------------------------------------------------------------
// Package helpers
// ---------------------------------------------------------------------------

// parseCSRFToken walks the join page HTML and returns the value of the hidden
// input nested inside the <auto-check src="/email_validity_checks"> element.
func parseCSRFToken(r io.Reader) (string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return "", fmt.Errorf("parsing HTML: %w", err)
	}

	var token string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if token != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "auto-check" && hasAttr(n, "src", validityCheckPath) {
			if v, ok := findHiddenInputValue(n); ok {
				token = v
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	if token == "" {
		return "", fmt.Errorf("CSRF authenticity token not found on join page")
	}
	return token, nil
}

// findHiddenInputValue returns the value attribute of the first descendant
// <input type="hidden"> of n.
func findHiddenInputValue(n *html.Node) (string, bool) {
	var value string
	var found bool
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if found {
			return
		}
		if node.Type == html.ElementNode && node.Data == "input" && hasAttr(node, "type", "hidden") {
			if v, ok := attrValue(node, "value"); ok {
				value = v
				found = true
				return
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return value, found
}

// hasAttr reports whether n has an attribute key equal to want.
func hasAttr(n *html.Node, key, want string) bool {
	v, ok := attrValue(n, key)
	return ok && v == want
}

// attrValue returns the value of n's attribute key.
func attrValue(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// cookieHeader builds a "name=value; ..." Cookie header string from cookies.
func cookieHeader(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// randomHexName returns 30 hex chars from 15 random bytes, mirroring the Python
// reference's binascii.b2a_hex(os.urandom(15)).
func randomHexName() string {
	b := make([]byte, 15)
	// crypto/rand.Read is used for name uniqueness within a single run; it never
	// fails on the platforms we target, so the error is intentionally ignored.
	_, _ = rand.Read(b)
	var sb strings.Builder
	for _, x := range b {
		sb.WriteString(strconv.FormatInt(int64(x>>4), 16))
		sb.WriteString(strconv.FormatInt(int64(x&0x0f), 16))
	}
	return sb.String()
}

// sleepCtx waits for d or returns ctx.Err() if ctx is canceled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
