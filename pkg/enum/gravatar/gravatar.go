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

// Package gravatar provides email-account enumeration via the Gravatar avatar
// endpoint. This is the single source of truth for the Gravatar
// account-existence check, reused by the internal enum oracle plugin and
// consumable via the Brutus API.
package gravatar

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const DefaultBaseURL = "https://www.gravatar.com"

// HashEmail returns the Gravatar hash of email: the MD5 hex digest of the
// normalized (lower-cased, whitespace-trimmed) address, as required by the
// Gravatar avatar API.
func HashEmail(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	sum := md5.Sum([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// Result is the outcome of checking a single email against the Gravatar avatar
// endpoint.
type Result struct {
	Email string
	// First and Last are copied from the originating enum.Target when
	// enumerating via EnumerateTargetsWith. They are empty when the address
	// arrived through EnumerateWith, which takes bare addresses and so has no
	// name to carry. This package never derives a name from the local part.
	First    string
	Last     string
	Hash     string
	Exists   bool
	Error    error
	Duration time.Duration
}

// Checker performs Gravatar account-existence checks via the avatar endpoint.
// It is safe for concurrent use.
type Checker struct {
	baseURL string
	timeout time.Duration
	client  *http.Client
}

// NewChecker creates a Checker with the given timeout. Pass "" for baseURL to
// use the default Gravatar endpoint. Pass "" for proxyURL for a direct
// (non-proxied) client; when proxyURL is non-empty the checker's client routes
// through it (honoring the --proxy flag), mirroring the Microsoft 365 checker.
func NewChecker(baseURL, proxyURL string, timeout time.Duration) (*Checker, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	client := enum.NewEnumHTTPClient(timeout)
	if proxyURL != "" {
		c, err := enum.NewEnumHTTPClientWithProxy(timeout, proxyURL)
		if err != nil {
			return nil, fmt.Errorf("gravatar: configuring proxy: %w", err)
		}
		client = c
	}
	return &Checker{
		baseURL: baseURL,
		timeout: timeout,
		client:  client,
	}, nil
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// Enumerate looks up each email using a bounded worker pool, applying rate
// limiting and jitter when rateLimit > 0. Results preserve input order. It is a
// thin wrapper around EnumerateWith with no per-result callback.
func (c *Checker) Enumerate(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration) []Result {
	return c.EnumerateWith(ctx, emails, threads, rateLimit, jitter, nil)
}

// EnumerateWith runs enumeration over bare addresses. It is a thin adapter over
// EnumerateTargetsWith, which holds the single implementation: each address is
// promoted to a nameless enum.Target. Because a bare address says nothing about
// whose it is, every returned Result has empty First/Last — callers that know
// the name behind an address should use EnumerateTargetsWith instead.
//
// The signature, ordering and callback semantics are unchanged; see
// EnumerateTargetsWith for the callback contract.
func (c *Checker) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	targets := make([]enum.Target, len(emails))
	for i, email := range emails {
		targets[i] = enum.Target{Email: email}
	}
	return c.EnumerateTargetsWith(ctx, targets, threads, rateLimit, jitter, onResult)
}

// newError builds the Result for failures the worker pool detects rather than
// the probe: cancellation, a rate-limiter error, a nil result from CheckAccount,
// and panic recovery.
//
// Hash is NOT decorative and must not be dropped: a gravatar Result identifies
// its subject by the avatar hash as well as the address, and every failure
// result this package produced before the shared-worker refactor carried it. A
// generic zero-value construction in the worker would silently erase it, which
// is exactly why NewError is a per-package hook. Note the deliberate asymmetry:
// Email echoes the caller's input verbatim while Hash is computed from the
// normalized (lower-cased, trimmed) form, because that is what the avatar API
// keys on.
func newError(email string, err error) Result {
	return Result{Email: email, Hash: HashEmail(email), Error: err}
}

// worker returns the shared bounded worker pool configured for this checker. It
// is a method (rather than inline in EnumerateTargetsWith) so tests can assert
// the four hooks — in particular the Label that drives the panic diagnostics,
// and newError's field shape — without running a pool.
func (c *Checker) worker() enum.TargetWorker[Result] {
	return enum.TargetWorker[Result]{
		Label: "gravatar enum",
		// CheckAccount returns *Result, so the nil guard lives here rather than
		// in the shared worker: the message is this package's text, and keeping
		// Check value-returning keeps a pointer/value duality out of the generic.
		Check: func(ctx context.Context, email string) Result {
			r := c.CheckAccount(ctx, email)
			if r == nil {
				return newError(email, fmt.Errorf("gravatar enum: nil result for %s", email))
			}
			return *r
		},
		NewError:  newError,
		StampName: func(r *Result, t enum.Target) { r.First, r.Last = t.First, t.Last },
	}
}

// EnumerateTargetsWith runs enumeration with bounded concurrency over targets
// that carry the name behind each address, and invokes onResult (if non-nil) for
// each completed result, serialized so callers can print/stream safely. It
// returns all results in input order.
//
// The name travels with the target rather than being recovered afterwards, so a
// consumer of this package never has to reverse-derive a name from the local
// part — a lossy guess for initial-based formats, where "jsmith" could be John,
// James or Jane. Each Result is stamped with the name of the target that
// produced it (never a neighboring target's).
//
// A name is a property of the address, not of the check outcome, so the stamp is
// applied on every path: a completed check, context cancellation, a rate-limiter
// error, cancellation during jitter, a nil result from CheckAccount, and panic
// recovery. A failed probe still reports whose address failed. Targets without a
// name (operator-supplied addresses) stay nameless; no name is ever invented.
//
// onResult is called under the same mutex that guards the results slice, so
// callback invocations never interleave and never race the slice. The callback
// must therefore be cheap and self-contained: it may write to an io.Writer or
// update counters, but it must NOT call back into the Checker (doing so risks
// deadlock and defeats the serialization guarantee).
//
// The pool itself is enum.TargetWorker; see its doc comment for the full contract.
func (c *Checker) EnumerateTargetsWith(ctx context.Context, targets []enum.Target, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
	return c.worker().Run(ctx, targets, threads, rateLimit, jitter, onResult)
}

// CheckAccount tests if an email account has a registered Gravatar by requesting
// the avatar for its hash with d=404 (so a missing avatar returns 404 rather
// than a default image). HTTP 200 means the account exists, 404 means it does
// not, and any other status is treated as a service error.
//
// If ctx carries a shared enum HTTP client (via enum.WithHTTPClient — set for a
// run to honor --proxy and connection pooling), that client is used; otherwise
// the Checker's own client is used.
func (c *Checker) CheckAccount(ctx context.Context, email string) *Result {
	start := time.Now()
	hash := HashEmail(email)
	result := &Result{Email: email, Hash: hash}
	defer func() { result.Duration = time.Since(start) }()

	url := fmt.Sprintf("%s/avatar/%s?d=404&s=1", c.baseURL, hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	client := enum.HTTPClientFromContext(ctx)
	if client == nil {
		client = c.client
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the body (within the shared read limit) so the connection can be
	// reused; the status code alone determines existence.
	if _, err := enum.ReadResponseBody(resp, 0); err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		return result
	}

	switch resp.StatusCode {
	case http.StatusOK:
		result.Exists = true
	case http.StatusNotFound:
		result.Exists = false
	default:
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return result
}
