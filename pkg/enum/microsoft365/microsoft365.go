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

// Package microsoft365 provides O365 account enumeration via the
// GetCredentialType API. This is the single source of truth for the Microsoft
// 365 account-existence check, reused by the internal enum oracle plugin and
// consumable via the Brutus API.
package microsoft365

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const DefaultBaseURL = "https://login.microsoftonline.com"

// IfExistsResult values returned by the GetCredentialType API.
const (
	IfExistsResultExists          = 0
	IfExistsResultNotExists       = 1
	IfExistsResultDifferentTenant = 5
	IfExistsResultDomainHint      = 6
)

type credTypeRequest struct {
	Username string `json:"Username"`
}

type credTypeResponse struct {
	IfExistsResult        int    `json:"IfExistsResult"`
	ThrottleStatus        int    `json:"ThrottleStatus"`
	FederationRedirectUrl string `json:"FederationRedirectUrl,omitempty"`
}

// Result is the outcome of checking a single email against the
// GetCredentialType API.
type Result struct {
	Email string
	// First and Last are copied from the originating enum.Target when
	// enumerating via EnumerateTargetsWith. They are empty when the address
	// arrived through EnumerateWith, which takes bare addresses and so has no
	// name to carry. This package never derives a name from the local part.
	First          string
	Last           string
	Exists         bool
	IfExistsResult int
	Federated      bool
	FederationURL  string
	Error          error
	Duration       time.Duration
}

// Checker performs O365 account-existence checks via GetCredentialType. It is
// safe for concurrent use.
type Checker struct {
	baseURL string
	timeout time.Duration
	client  *http.Client
}

// NewChecker creates a Checker with the given timeout. Pass "" for baseURL to
// use the default Microsoft login endpoint. Pass "" for proxyURL for a direct
// (non-proxied) client; when proxyURL is non-empty the checker's client routes
// through it (honoring the --proxy flag), mirroring the Google enumerator.
func NewChecker(baseURL, proxyURL string, timeout time.Duration) (*Checker, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	client := enum.NewEnumHTTPClient(timeout)
	if proxyURL != "" {
		c, err := enum.NewEnumHTTPClientWithProxy(timeout, proxyURL)
		if err != nil {
			return nil, fmt.Errorf("microsoft365: configuring proxy: %w", err)
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
// and panic recovery. microsoft365's failure results carry no fields beyond the
// address and the error.
func newError(email string, err error) Result {
	return Result{Email: email, Error: err}
}

// worker returns the shared bounded worker pool configured for this checker. It
// is a method (rather than inline in EnumerateTargetsWith) so tests can assert
// the four hooks — in particular the Label that drives the panic diagnostics,
// and newError's field shape — without running a pool.
func (c *Checker) worker() enum.TargetWorker[Result] {
	return enum.TargetWorker[Result]{
		Label: "microsoft365 enum",
		// CheckAccount returns *Result, so the nil guard lives here rather than
		// in the shared worker: the message is this package's text, and keeping
		// Check value-returning keeps a pointer/value duality out of the generic.
		Check: func(ctx context.Context, email string) Result {
			r := c.CheckAccount(ctx, email)
			if r == nil {
				return newError(email, fmt.Errorf("microsoft365 enum: nil result for %s", email))
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

// CheckAccount tests if an email account exists on Microsoft 365 via the
// GetCredentialType API. It handles IfExistsResult codes 0/1/5/6, throttle
// detection, and federation redirect URL extraction.
//
// If ctx carries a shared enum HTTP client (via enum.WithHTTPClient — set for a
// run to honor --proxy and connection pooling), that client is used; otherwise
// the Checker's own client is used.
func (c *Checker) CheckAccount(ctx context.Context, email string) *Result {
	start := time.Now()
	result := &Result{Email: email}
	defer func() { result.Duration = time.Since(start) }()

	body, err := json.Marshal(credTypeRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		return result
	}

	url := c.baseURL + "/common/GetCredentialType"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

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

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		return result
	}

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		return result
	}
	var credResp credTypeResponse
	if err := json.Unmarshal(raw, &credResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		return result
	}

	if credResp.ThrottleStatus != 0 {
		result.Error = fmt.Errorf("throttled by Microsoft 365")
		return result
	}

	result.IfExistsResult = credResp.IfExistsResult

	switch credResp.IfExistsResult {
	case IfExistsResultExists, IfExistsResultDifferentTenant, IfExistsResultDomainHint:
		result.Exists = true
	}

	if credResp.FederationRedirectUrl != "" {
		result.Federated = true
		result.FederationURL = credResp.FederationRedirectUrl
	}

	return result
}
