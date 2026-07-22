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

package github

import (
	"bytes"
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

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// Existence enumeration (unauthenticated)
// ---------------------------------------------------------------------------

// Enumerate checks each email's existence using a bounded worker pool, applying
// rate limiting and jitter when rateLimit > 0. Results preserve input order. It
// is a thin wrapper around EnumerateWith with no per-result callback.
func (e *Enumerator) Enumerate(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration) []Result {
	return e.EnumerateWith(ctx, emails, threads, rateLimit, jitter, nil)
}

// EnumerateWith runs existence enumeration with bounded concurrency and invokes
// onResult (if non-nil) for each completed result, serialized so callers can
// print/stream safely. It still returns all results in input order.
//
// The session (CSRF token + cookies) is established ONCE before the worker pool
// and shared read-only across workers. If session establishment fails, every
// Result is returned carrying that error.
//
// onResult is called under the same mutex that guards the results slice, so
// callback invocations never interleave and never race the slice. The callback
// must be cheap and self-contained and must NOT call back into the Enumerator.
func (e *Enumerator) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]Result, len(emails))
	var mu sync.Mutex
	record := func(i int, res Result) {
		mu.Lock()
		defer mu.Unlock()
		results[i] = res
		if onResult != nil {
			onResult(res)
		}
	}

	sess, err := e.establishSession(ctx)
	if err != nil {
		// Without a session no checks are possible; surface the error on every
		// result so the caller (and JSONL output) reflects the failure per email.
		for i, email := range emails {
			record(i, Result{Email: email, Error: err})
		}
		return results
	}

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

	for i, email := range emails {
		i, email := i, email
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "github enum: panic checking %s: %v\n%s\n", email, r, debug.Stack())
					record(i, Result{
						Email: email,
						Error: fmt.Errorf("github enum: panicked: %v", r),
					})
				}
			}()

			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					return nil
				}
				if jitter > 0 {
					delay := time.Duration(rand.Int63n(int64(jitter)))
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return nil
					}
				}
			}

			record(i, e.checkEmail(ctx, sess, email))
			return nil
		})
	}

	// Worker goroutines never return a non-nil error (per-email failures are
	// encoded in each Result), so the returned error is always nil.
	_ = g.Wait()
	return results
}

// ---------------------------------------------------------------------------
// Existence helpers
// ---------------------------------------------------------------------------

// establishSession fetches the join page, parses the CSRF token, and runs the
// sanity check, retrying on transient failures. GitHub's signup page applies
// intermittent, rate/reputation-based bot detection that returns a token-less
// stub (commonly HTTP 403); a single such response would otherwise fail the
// whole run. Retries use e.existenceBackoff / e.existenceMaxRetries (tuned to a
// short delay + higher ceiling under --rotating-proxy, where each retry egresses
// a fresh exit IP). A 200 response whose HTML lacks the token is NOT retried —
// that signals a genuine endpoint change, so it fails fast.
func (e *Enumerator) establishSession(ctx context.Context) (*session, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		sess, retryable, err := e.tryEstablishSession(ctx)
		if err == nil {
			return sess, nil
		}
		lastErr = err
		if !retryable || attempt >= e.existenceMaxRetries {
			return nil, lastErr
		}
		if serr := e.sleep(ctx, e.existenceBackoff); serr != nil {
			return nil, serr
		}
	}
}

// tryEstablishSession performs ONE attempt to GET the join page, parse the CSRF
// token, and run the sanity check. The bool reports whether a non-nil error is
// worth retrying: transport failures, non-200 responses (the intermittent bot/
// rate block), and transient sanity-check failures are retryable; a 200 with no
// parseable token is not (the page contract changed).
func (e *Enumerator) tryEstablishSession(ctx context.Context) (*session, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.webBaseURL+joinPath, http.NoBody)
	if err != nil {
		return nil, false, fmt.Errorf("github enum: creating join request: %w", err)
	}
	// GitHub's signup page returns 403 (a token-less stub) to requests that lack an
	// Accept header — Go's net/http omits it by default. The browser User-Agent is
	// already injected at the transport layer (enum.WithUserAgent in NewEnumerator);
	// a browser-like Accept is the other half of that "look like a normal client"
	// pattern, so the join page returns the real CSRF-bearing HTML.
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("github enum: join request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// GitHub serves a token-less stub (commonly HTTP 403) to requests its bot/
		// rate detection dislikes. This is intermittent, so it is retryable — with
		// --rotating-proxy each retry uses a fresh exit IP.
		return nil, true, fmt.Errorf("github enum: join page returned HTTP %d (GitHub bot/rate detection on the signup page; intermittent — with --rotating-proxy each retry uses a fresh exit IP)", resp.StatusCode)
	}

	// Bounded read — reuses enum.ReadResponseBody (1 MB default) so a hostile or
	// misbehaving join endpoint cannot exhaust memory via an unbounded HTML body.
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, true, fmt.Errorf("github enum: reading join page: %w", err)
	}

	csrf, err := parseCSRFToken(bytes.NewReader(body))
	if err != nil {
		// 200 but no token: the endpoint contract likely changed. Retrying will
		// not help, so fail fast.
		return nil, false, fmt.Errorf("github enum: parsing join page: %w", err)
	}

	sess := &session{
		csrfToken:    csrf,
		cookieHeader: cookieHeader(resp.Cookies()),
	}

	// Sanity check: a random address should be available (200). If not, warn —
	// the endpoint contract may have changed.
	sanityEmail := e.newName() + "@foobar.com"
	exists, err := e.postValidity(ctx, sess, sanityEmail)
	if err != nil {
		return nil, true, fmt.Errorf("github enum: sanity check failed: %w", err)
	}
	if exists {
		fmt.Fprintf(os.Stderr,
			"github enum: WARNING sanity-check address %q returned in-use; the email_validity_checks endpoint may have changed (results may be unreliable)\n",
			sanityEmail)
	}

	return sess, false, nil
}

// checkEmail POSTs a single email to the validity endpoint and maps the result.
// HTTP 429 is retried (bounded, ctx-aware) after sleeping. Transport failures
// and exhausted retries are encoded in the Result's Error field.
func (e *Enumerator) checkEmail(ctx context.Context, sess *session, email string) Result {
	res := Result{Email: email}
	exists, err := e.postValidity(ctx, sess, email)
	if err != nil {
		res.Error = err
		return res
	}
	res.Exists = exists
	return res
}

// postValidity POSTs email to {web}/email_validity_checks with the session's
// CSRF token and cookies. It returns true when the address is in use (HTTP 422),
// false when available (HTTP 200), retrying on HTTP 429 up to existenceMaxRetries.
// HTTP 403 (GitHub blocking the exit IP) is also retried, but ONLY under
// --rotating-proxy, where each retry egresses a fresh IP; in non-rotating mode a
// 403 is a persistently blocked IP and fails fast.
func (e *Enumerator) postValidity(ctx context.Context, sess *session, email string) (bool, error) {
	form := url.Values{}
	form.Set("authenticity_token", sess.csrfToken)
	form.Set("value", email)
	body := form.Encode()

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.webBaseURL+validityCheckPath, strings.NewReader(body))
		if err != nil {
			return false, fmt.Errorf("creating validity request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		if sess.cookieHeader != "" {
			req.Header.Set("Cookie", sess.cookieHeader)
		}

		resp, err := e.httpClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("validity request failed: %w", err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()

		switch status {
		case http.StatusUnprocessableEntity: // 422 — in use (account exists)
			return true, nil
		case http.StatusOK: // 200 — available (no account)
			return false, nil
		case http.StatusTooManyRequests: // 429 — rate limited
			if attempt >= e.existenceMaxRetries {
				return false, fmt.Errorf("rate limited (HTTP 429) after %d retries", attempt)
			}
			if err := e.sleep(ctx, e.existenceBackoff); err != nil {
				return false, err
			}
			continue
		case http.StatusForbidden: // 403 — GitHub blocked this exit IP
			// GitHub blocks ~80-87% of datacenter/rotating-proxy exit IPs on the
			// validity endpoint. Retrying only helps under --rotating-proxy, where
			// each retry opens a fresh connection and thus a fresh exit IP (see
			// DisableKeepAlives in NewEnumerator). In non-rotating mode a 403 is a
			// persistently blocked IP, so retrying would just add ~10s/email of
			// pointless latency — fail fast there. Retry accounting mirrors 429.
			if !e.rotatingProxy {
				return false, fmt.Errorf("unexpected status %d from validity endpoint", status)
			}
			if attempt >= e.existenceMaxRetries {
				return false, fmt.Errorf("validity check blocked (HTTP 403) after %d retries", attempt)
			}
			if err := e.sleep(ctx, e.existenceBackoff); err != nil {
				return false, err
			}
			continue
		default:
			return false, fmt.Errorf("unexpected status %d from validity endpoint", status)
		}
	}
}
