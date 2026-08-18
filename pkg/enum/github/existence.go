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
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

// EnumerateWith runs existence enumeration over bare addresses. It is a thin
// adapter over EnumerateTargetsWith, which holds the single implementation: each
// address is promoted to a nameless enum.Target. Because a bare address says
// nothing about whose it is, every returned Result has empty First/Last —
// callers that know the name behind an address should use EnumerateTargetsWith
// instead.
//
// The signature, ordering and callback semantics are unchanged; see
// EnumerateTargetsWith for the session gate, the callback contract, and for the
// one deliberate behavior change this delegation brings: abort paths now record
// a result rather than dropping it.
func (e *Enumerator) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	targets := make([]enum.Target, len(emails))
	for i, email := range emails {
		targets[i] = enum.Target{Email: email}
	}
	return e.EnumerateTargetsWith(ctx, targets, threads, rateLimit, jitter, onResult)
}

// newError builds the Result for failures detected outside the probe: session
// establishment, cancellation, a rate-limiter error, cancellation during jitter,
// and panic recovery. github's failure results carry no fields beyond the
// address and the error.
func newError(email string, err error) Result {
	return Result{Email: email, Error: err}
}

// worker returns the shared bounded worker pool bound to an established session.
// The session is a parameter rather than enumerator state because it is
// established once per EnumerateTargetsWith call and shared read-only by every
// worker.
//
// It is a method (rather than inline in EnumerateTargetsWith) so tests can
// assert the four hooks — in particular the Label that drives the panic
// diagnostics, and newError's field shape — without running a pool or a live
// join/validity endpoint.
func (e *Enumerator) worker(sess *session) enum.TargetWorker[Result] {
	return enum.TargetWorker[Result]{
		Label: "github enum",
		Check: func(ctx context.Context, email string) Result {
			return e.checkEmail(ctx, sess, email)
		},
		NewError:  newError,
		StampName: func(r *Result, t enum.Target) { r.First, r.Last = t.First, t.Last },
	}
}

// EnumerateTargetsWith runs existence enumeration with bounded concurrency over
// targets that carry the name behind each address, and invokes onResult (if
// non-nil) for each completed result, serialized so callers can print/stream
// safely. It returns all results in input order.
//
// The name travels with the target rather than being recovered afterwards, so a
// consumer of this package never has to reverse-derive a name from the local
// part — a lossy guess for initial-based formats, where "jsmith" could be John,
// James or Jane. Each Result is stamped with the name of the target that
// produced it (never a neighboring target's).
//
// A name is a property of the address, not of the check outcome, so the stamp is
// applied on every path: a completed check, session-establishment failure,
// context cancellation, a rate-limiter error, cancellation during jitter, and
// panic recovery. A failed probe still reports whose address failed. Targets
// without a name (operator-supplied addresses) stay nameless; no name is ever
// invented.
//
// The session (CSRF token + cookies) is established ONCE before the worker pool
// and shared read-only across workers. If session establishment fails, no check
// is possible, so every Target is returned carrying that error — still stamped
// with its name, and still delivered to onResult exactly once — rather than
// running a pool that would fail identically for every address.
//
// Behavior change (deliberate): before this package delegated to
// enum.TargetWorker, the pool's own abort paths returned without recording,
// leaving that slot a zero Result (Email empty, Error nil) and never firing
// onResult. Every abort now records newError(email, <cause>) and fires onResult
// exactly once, matching google, microsoft365 and gravatar. An interrupted run
// therefore emits one error result per un-probed address instead of dropping it
// silently. The session-failure gate above is unaffected — it always filled
// every slot.
//
// onResult is called under the same mutex that guards the results slice, so
// callback invocations never interleave and never race the slice. The callback
// must be cheap and self-contained and must NOT call back into the Enumerator.
//
// The pool itself is enum.TargetWorker; see its doc comment for the full contract.
func (e *Enumerator) EnumerateTargetsWith(ctx context.Context, targets []enum.Target, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	sess, err := e.establishSession(ctx)
	if err != nil {
		// Without a session no checks are possible; surface the error on every
		// result so the caller (and JSONL output) reflects the failure per email.
		// This gate runs before the pool, on this goroutine, so no lock is
		// needed — but the stamp and the exactly-once callback contract still
		// hold, exactly as they do inside the pool.
		results := make([]Result, len(targets))
		for i, t := range targets {
			res := newError(t.Email, err)
			res.First, res.Last = t.First, t.Last
			results[i] = res
			if onResult != nil {
				onResult(res)
			}
		}
		return results
	}

	return e.worker(sess).Run(ctx, targets, threads, rateLimit, jitter, onResult)
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
	maxAttempts := e.existenceMaxRetries + 1
	for attempt := 0; ; attempt++ {
		if e.OnSessionProgress != nil {
			e.OnSessionProgress(attempt+1, maxAttempts, lastErr)
		}
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
