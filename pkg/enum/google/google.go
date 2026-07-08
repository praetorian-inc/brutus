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

// Package google provides unauthenticated Google Workspace account enumeration.
// It is the single source of truth for the Google account-existence checks
// (AccountChooser SSO detection and the GXLU Gmail probe), reused both by the
// internal enum oracle plugin and by the "enum google" command. Unlike the
// Teams enumerator, these checks are unauthenticated — there are no tokens,
// credential stores, or refresh logic.
package google

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Method identifies which oracle confirmed an account's existence.
type Method string

const (
	// MethodWorkspaceSSO means existence was confirmed by the AccountChooser
	// SSO/SAML redirect (a Workspace domain with SSO configured).
	MethodWorkspaceSSO Method = "workspace-sso"
	// MethodGmail means existence was confirmed by the GXLU Gmail probe
	// (a Gmail-enabled account).
	MethodGmail Method = "gmail"
	// MethodNone means no oracle confirmed existence.
	MethodNone Method = ""
)

// Result is the outcome of checking a single email. IdP is the SSO identity
// provider host parsed from the AccountChooser redirect Location (workspace-sso
// only; empty when only the SAML header was present or for gmail). IdP is
// server-controlled and is NOT sanitized here; sanitization happens at the
// output layer. There are no secrets in this flow, so Error carries the raw
// transport error.
type Result struct {
	Email  string
	Exists bool
	Method Method
	IdP    string
	Error  error
}

const (
	accountChooserBaseURLDefault = "https://accounts.google.com"
	gxluBaseURLDefault           = "https://mail.google.com"
)

// Enumerator performs unauthenticated Google Workspace account enumeration via
// the AccountChooser SSO redirect and the GXLU Gmail probe. It is safe for
// concurrent use.
type Enumerator struct {
	httpClient *http.Client

	// Base URLs for the two endpoints; defaults point at the real Google hosts
	// and are overridable by tests (mirroring the teams Enumerator pattern).
	accountChooserBaseURL string
	gxluBaseURL           string
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewEnumerator builds an Enumerator. The HTTP client is built via
// brutus.NewHTTPClientWithProxy so the SOCKS5 --proxy flag works. The supplied
// timeout is used directly as the per-request budget.
func NewEnumerator(proxyURL string, timeout time.Duration) (*Enumerator, error) {
	httpClient, err := brutus.NewHTTPClientWithProxy(timeout, nil, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("google enum: configuring HTTP client: %w", err)
	}

	return &Enumerator{
		httpClient:            httpClient,
		accountChooserBaseURL: accountChooserBaseURLDefault,
		gxluBaseURL:           gxluBaseURLDefault,
	}, nil
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// Enumerate looks up each email using a bounded worker pool, applying rate
// limiting and jitter when rateLimit > 0. Results preserve input order. It is a
// thin wrapper around EnumerateWith with no per-result callback.
func (e *Enumerator) Enumerate(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration) []Result {
	return e.EnumerateWith(ctx, emails, threads, rateLimit, jitter, nil)
}

// EnumerateWith runs enumeration with bounded concurrency and invokes onResult
// (if non-nil) for each completed result, serialized so callers can print/stream
// safely. It still returns all results in input order.
//
// onResult is called under the same mutex that guards the results slice, so
// callback invocations never interleave and never race the slice. The callback
// must therefore be cheap and self-contained: it may write to an io.Writer or
// update counters, but it must NOT call back into the Enumerator (doing so risks
// deadlock and defeats the serialization guarantee).
func (e *Enumerator) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	// Normalize thread count: 0 would deadlock errgroup.SetLimit (no goroutine
	// can ever run) and a negative value means unbounded. Clamp to a safe
	// positive default of 1 (serial execution).
	if threads <= 0 {
		threads = 1
	}
	g.SetLimit(threads)

	var limiter *rate.Limiter
	if rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(rateLimit), 1)
	}

	results := make([]Result, len(emails))
	var mu sync.Mutex

	// record stores a completed result and, under the same lock, invokes the
	// caller's callback so streamed output is serialized and slice-safe.
	record := func(i int, res Result) {
		mu.Lock()
		defer mu.Unlock()
		results[i] = res
		if onResult != nil {
			onResult(res)
		}
	}

	for i, email := range emails {
		i, email := i, email
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "google enum: panic checking %s: %v\n%s\n", email, r, debug.Stack())
					record(i, Result{
						Email: email,
						Error: fmt.Errorf("google enum: panicked: %v", r),
					})
				}
			}()

			select {
			case <-ctx.Done():
				// Record before returning so every index is filled and the callback fires exactly once per email.
				record(i, Result{Email: email, Error: ctx.Err()})
				return nil
			default:
			}

			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					// Record before returning so every index is filled and the callback fires exactly once per email.
					record(i, Result{Email: email, Error: err})
					return nil
				}
				if jitter > 0 {
					delay := time.Duration(rand.Int63n(int64(jitter)))
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						// Record before returning so every index is filled and the callback fires exactly once per email.
						record(i, Result{Email: email, Error: ctx.Err()})
						return nil
					}
				}
			}

			record(i, e.CheckAccount(ctx, email))
			return nil
		})
	}

	// Discarding g.Wait()'s error is deliberate: worker goroutines never return
	// a non-nil error (per-email failures are encoded in each Result), so the
	// returned error is always nil.
	_ = g.Wait()
	return results
}

// CheckAccount checks whether a single Google account exists, trying the
// AccountChooser SSO redirect first and falling back to the GXLU Gmail probe.
// It never returns an error directly; transport failures are encoded in the
// returned Result's Error field with Exists=false.
func (e *Enumerator) CheckAccount(ctx context.Context, email string) Result {
	res := Result{Email: email, Method: MethodNone}

	// AccountChooser (primary) — detects Workspace accounts on SSO domains.
	exists, idp, err := e.checkAccountChooser(ctx, email)
	if err != nil {
		res.Error = err
		return res
	}
	if exists {
		res.Exists = true
		res.Method = MethodWorkspaceSSO
		res.IdP = idp
		return res
	}

	// GXLU (fallback) — detects Gmail-enabled accounts.
	exists, err = e.checkGXLU(ctx, email)
	if err != nil {
		res.Error = err
		return res
	}
	if exists {
		res.Exists = true
		res.Method = MethodGmail
		return res
	}

	return res
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// checkAccountChooser checks whether Google redirects to a SAML IdP for this
// email. SSO-configured domains redirect valid accounts to their IdP; invalid
// accounts redirect back to accounts.google.com/ServiceLogin. It returns the
// IdP host (parsed from the redirect Location) when one is available.
//
// The shared proxied client follows redirects by default, so a per-request
// clone with CheckRedirect=ErrUseLastResponse is used to inspect the 302
// Location header while keeping the proxy transport.
func (e *Enumerator) checkAccountChooser(ctx context.Context, email string) (federated bool, host string, err error) {
	u := e.accountChooserBaseURL + "/AccountChooser?Email=" + url.QueryEscape(email) + "&continue=https://mail.google.com/mail/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, "", fmt.Errorf("creating AccountChooser request: %w", err)
	}

	// Clone the proxied client so redirects are not followed (keeping the proxy
	// transport); we need to inspect the 302 Location header.
	client := *e.httpClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("AccountChooser request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	location := resp.Header.Get("Location")

	// A SAML redirect header is present only for valid accounts on SSO domains.
	if resp.Header.Get("Google-Accounts-SAML") != "" {
		return true, idpHost(location), nil
	}

	// A Location that redirects to a non-Google host is an IdP redirect.
	if location != "" && !strings.Contains(location, "accounts.google.com") && !strings.Contains(location, "google.com/ServiceLogin") {
		return true, idpHost(location), nil
	}

	return false, "", nil
}

// checkGXLU checks whether an email has a Gmail-enabled Google account.
// GET {gxluBaseURL}/mail/gxlu?email=USER@DOMAIN — a GMAIL_AT cookie in the
// response indicates the account exists. The default proxied client (which
// follows redirects) is used as-is, since GXLU does not rely on inspecting a
// redirect.
func (e *Enumerator) checkGXLU(ctx context.Context, email string) (bool, error) {
	gxluURL := e.gxluBaseURL + "/mail/gxlu?email=" + url.QueryEscape(email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gxluURL, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("creating GXLU request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("GXLU request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "GMAIL_AT" {
			return true, nil
		}
	}

	return false, nil
}

// idpHost parses the host out of a redirect Location URL, returning "" when the
// location is empty or unparseable.
func idpHost(location string) string {
	if location == "" {
		return ""
	}
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Host
}
