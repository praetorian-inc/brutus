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
	"math/rand"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

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
	Email          string
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

// EnumerateWith runs enumeration with bounded concurrency and invokes onResult
// (if non-nil) for each completed result, serialized so callers can print/stream
// safely. It still returns all results in input order.
//
// onResult is called under the same mutex that guards the results slice, so
// callback invocations never interleave and never race the slice. The callback
// must therefore be cheap and self-contained: it may write to an io.Writer or
// update counters, but it must NOT call back into the Checker (doing so risks
// deadlock and defeats the serialization guarantee).
func (c *Checker) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(Result)) []Result {
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
					fmt.Fprintf(os.Stderr, "microsoft365 enum: panic checking %s: %v\n%s\n", email, r, debug.Stack())
					record(i, Result{
						Email: email,
						Error: fmt.Errorf("microsoft365 enum: panicked: %v", r),
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

			r := c.CheckAccount(ctx, email)
			if r == nil {
				record(i, Result{
					Email: email,
					Error: fmt.Errorf("microsoft365 enum: nil result for %s", email),
				})
				return nil
			}
			record(i, *r)
			return nil
		})
	}

	// Discarding g.Wait()'s error is deliberate: worker goroutines never return
	// a non-nil error (per-email failures are encoded in each Result), so the
	// returned error is always nil.
	_ = g.Wait()
	return results
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
