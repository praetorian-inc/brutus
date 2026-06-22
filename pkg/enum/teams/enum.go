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

package teams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Existence is the tri-state (plus unknown) result of a Teams user lookup.
type Existence string

const (
	// ExistenceYes means the user was found in the tenant directory.
	ExistenceYes Existence = "yes"
	// ExistenceNo means the lookup succeeded but no user matched.
	ExistenceNo Existence = "no"
	// ExistenceBlocked means the lookup was forbidden (HTTP 403): the user may
	// exist but the tenant blocks external/anonymous searches.
	ExistenceBlocked Existence = "blocked"
	// ExistenceUnknown means existence could not be determined (auth failure,
	// transport error, or unexpected status).
	ExistenceUnknown Existence = "unknown"
)

// EnumResult is the outcome of enumerating a single email. Server-provided
// strings (DisplayName, MRI, Availability, DeviceType) are NOT sanitized here;
// sanitization happens at the output layer. Token values never appear in this
// struct, in logs, or in Error.
type EnumResult struct {
	Email        string
	Exists       Existence
	DisplayName  string
	MRI          string
	Availability string
	DeviceType   string
	Error        error
}

// Enumerator performs corporate Microsoft Teams user enumeration against the
// Teams externalsearch and presence endpoints. It is safe for concurrent use.
type Enumerator struct {
	httpClient   *http.Client
	accessToken  string
	refreshToken string
	presence     bool
	refreshFn    func(ctx context.Context) (string, error)

	// Endpoint templates; defaults point at the real Teams hosts and are
	// overridable by tests (same package) by assigning these fields directly,
	// mirroring auth.go's deviceCodeBaseURL/tokenBaseURL override pattern.
	searchBaseURL   string // format string with a single %s for the escaped email
	presenceBaseURL string // full presence endpoint URL

	mu        sync.Mutex
	refreshed bool
}

const (
	searchURLFmt  = "https://teams.microsoft.com/api/mt/emea/beta/users/%s/externalsearchv3?includeTFLUsers=true"
	presenceURL   = "https://presence.teams.microsoft.com/v1/presence/getpresence/"
	clientVersion = "1415/1.0.0.2023031528"
	// enumUserAgent mimics the Teams web client so requests are not rejected as
	// non-browser traffic.
	enumUserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	maxEnumBody int64 = 64 << 10
)

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewEnumerator builds an Enumerator. The HTTP client is built via
// brutus.NewHTTPClientWithProxy so the SOCKS5 --proxy flag works.
//
// Unlike teams.NewClient (interactive device-code auth, which floors the
// timeout at 30s), enumeration is non-interactive and bulk, so the supplied
// timeout is used directly — callers control the per-request budget via the
// global --timeout flag.
func NewEnumerator(accessToken, refreshToken, proxyURL string, timeout time.Duration, presence bool) (*Enumerator, error) {
	httpClient, err := brutus.NewHTTPClientWithProxy(timeout, nil, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("teams enum: configuring HTTP client: %w", err)
	}

	return &Enumerator{
		httpClient:      httpClient,
		accessToken:     accessToken,
		refreshToken:    refreshToken,
		presence:        presence,
		searchBaseURL:   searchURLFmt,
		presenceBaseURL: presenceURL,
	}, nil
}

// SetRefreshFunc installs a callback used to obtain a fresh access token after
// a 401. It is called at most once per Enumerator (serialized). Install it only
// when a refresh token is available.
func (e *Enumerator) SetRefreshFunc(fn func(ctx context.Context) (string, error)) {
	e.refreshFn = fn
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// Enumerate looks up each email using a bounded worker pool, applying rate
// limiting and jitter when rateLimit > 0. Results preserve input order.
func (e *Enumerator) Enumerate(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration) []EnumResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)

	var limiter *rate.Limiter
	if rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(rateLimit), 1)
	}

	results := make([]EnumResult, len(emails))
	var mu sync.Mutex

	for i, email := range emails {
		i, email := i, email
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "teams enum: panic checking %s: %v\n%s\n", email, r, debug.Stack())
					mu.Lock()
					results[i] = EnumResult{
						Email:  email,
						Exists: ExistenceUnknown,
						Error:  fmt.Errorf("teams enum: panicked: %v", r),
					}
					mu.Unlock()
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

			res := e.EnumerateOne(ctx, email)
			mu.Lock()
			results[i] = res
			mu.Unlock()
			return nil
		})
	}

	// Discarding g.Wait()'s error is deliberate: worker goroutines never return
	// a non-nil error (per-email failures are encoded in each EnumResult), so the
	// returned error is always nil.
	_ = g.Wait()
	return results
}

// EnumerateOne performs the existence lookup (and optional presence lookup) for
// a single email. It never returns an error directly; failures are encoded in
// the returned EnumResult's Exists and Error fields. Token values never appear
// in Error.
func (e *Enumerator) EnumerateOne(ctx context.Context, email string) EnumResult {
	res := EnumResult{Email: email}

	users, status, err := e.search(ctx, email, e.token())
	if err == nil && status == http.StatusUnauthorized {
		// Retry once with a refreshed token, serialized to at most one refresh
		// per Enumerator across goroutines.
		if e.refreshFn != nil {
			token, refreshErr := e.refreshOnce(ctx)
			if refreshErr == nil {
				users, status, err = e.search(ctx, email, token)
			}
		}
	}

	switch {
	case err != nil:
		res.Exists = ExistenceUnknown
		res.Error = fmt.Errorf("teams enum: %w", err)
		return res
	case status == http.StatusOK:
		if len(users) == 0 {
			res.Exists = ExistenceNo
			return res
		}
		res.Exists = ExistenceYes
		res.DisplayName = users[0].DisplayName
		res.MRI = users[0].MRI
	case status == http.StatusForbidden:
		res.Exists = ExistenceBlocked
		return res
	case status == http.StatusUnauthorized:
		res.Exists = ExistenceUnknown
		if e.refreshFn == nil {
			res.Error = errors.New("teams enum: unauthorized (token invalid or expired)")
		}
		return res
	default:
		res.Exists = ExistenceUnknown
		res.Error = fmt.Errorf("teams enum: unexpected status %d", status)
		return res
	}

	// Presence is best-effort: failures are non-fatal and leave the fields empty.
	if e.presence && res.Exists == ExistenceYes && res.MRI != "" {
		if avail, device, ok := e.getPresence(ctx, res.MRI); ok {
			res.Availability = avail
			res.DeviceType = device
		}
	}

	return res
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// search issues the externalsearch lookup with the given bearer token. It
// returns the decoded users, the HTTP status, and a non-nil error only on
// transport/decode failure (never including the token).
func (e *Enumerator) search(ctx context.Context, email, token string) ([]searchUser, int, error) {
	endpoint := fmt.Sprintf(e.searchBaseURL, url.PathEscape(email))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, fmt.Errorf("building search request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Ms-Client-Version", clientVersion)
	req.Header.Set("User-Agent", enumUserAgent)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("search request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnumBody))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading search response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}

	var users []searchUser
	if err := json.Unmarshal(body, &users); err != nil {
		// A non-array (or otherwise non-matching) body decodes to a zero-length
		// slice, which the caller treats as "not found".
		return nil, resp.StatusCode, nil
	}
	return users, resp.StatusCode, nil
}

// getPresence fetches Teams presence for the given MRI. It returns ok=false on
// any failure (best-effort).
func (e *Enumerator) getPresence(ctx context.Context, mri string) (availability, deviceType string, ok bool) {
	reqBody, err := json.Marshal([]presenceRequest{{MRI: mri}})
	if err != nil {
		return "", "", false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.presenceBaseURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token())

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnumBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", "", false
	}

	var presences []presenceResponse
	if err := json.Unmarshal(body, &presences); err != nil || len(presences) == 0 {
		return "", "", false
	}
	return presences[0].Presence.Availability, presences[0].Presence.DeviceType, true
}

// refreshOnce returns the current access token, refreshing it at most once per
// Enumerator across goroutines. On the first successful call it updates the
// stored access token; subsequent calls return the already-refreshed token.
func (e *Enumerator) refreshOnce(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.refreshed {
		return e.accessToken, nil
	}
	token, err := e.refreshFn(ctx)
	if err != nil {
		return "", err
	}
	e.accessToken = token
	e.refreshed = true
	return token, nil
}

// token returns the current access token under e.mu so concurrent worker
// goroutines observe the value written by refreshOnce. It must never be called
// while already holding e.mu (e.g. from inside refreshOnce) to avoid deadlock.
func (e *Enumerator) token() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.accessToken
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map to the Teams response shapes)
// ---------------------------------------------------------------------------

type searchUser struct {
	DisplayName string `json:"displayName"`
	MRI         string `json:"mri"`
}

type presenceRequest struct {
	MRI string `json:"mri"`
}

type presenceResponse struct {
	Presence struct {
		Availability string `json:"availability"`
		DeviceType   string `json:"deviceType"`
	} `json:"presence"`
}
