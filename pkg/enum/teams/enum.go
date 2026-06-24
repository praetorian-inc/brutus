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

	// Tenant-configuration posture signals, parsed defensively from the
	// externalsearchv3 result (Type/TenantID/UserPrincipalName/ObjectID/
	// AccountEnabled/CoExistenceMode) and the presence response (SourceNetwork/
	// OutOfOfficeNote). Absent fields stay empty (AccountEnabled stays nil), so
	// existence behavior is never affected. These strings are server-provided
	// and are NOT sanitized here; sanitization happens at the output layer.
	Type              string
	TenantID          string
	UserPrincipalName string
	ObjectID          string
	AccountEnabled    *bool
	CoExistenceMode   string
	SourceNetwork     string
	OutOfOfficeNote   string
}

// TenantPosture is a tenant-level configuration verdict aggregated from the
// per-user EnumResults for a single target domain. It surfaces cross-tenant /
// external-access posture, presence visibility, out-of-office leakage, and
// observed coexistence/federation metadata.
type TenantPosture struct {
	Domain              string
	Total               int
	UsersFound          int    // Exists == ExistenceYes
	Blocked403          int    // Exists == ExistenceBlocked (HTTP 403)
	ExternalChatAllowed string // "open" | "blocked" | "unknown"
	FederatedObserved   bool   // any result with Type=="Federated" or SourceNetwork=="Federated"
	PresenceVisible     bool   // any result with non-empty Availability
	OOOExposed          int    // count with non-empty OutOfOfficeNote
	CoExistenceMode     string // first non-empty observed
}

// Enumerator performs corporate Microsoft Teams user enumeration against the
// Teams externalsearch and presence endpoints. It is safe for concurrent use.
type Enumerator struct {
	httpClient      *http.Client
	accessToken     string
	refreshToken    string
	presence        bool
	includeConsumer bool
	refreshFn       func(ctx context.Context) (string, error)

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
	enumUserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	maxEnumBody   int64 = 64 << 10
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

// SetIncludeConsumer controls whether consumer/personal (8:live:) Teams
// accounts count as hits. Default false: only corporate (8:orgid:) matches
// are treated as existing; a consumer-only match is reported as not found.
func (e *Enumerator) SetIncludeConsumer(v bool) { e.includeConsumer = v }

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// Enumerate looks up each email using a bounded worker pool, applying rate
// limiting and jitter when rateLimit > 0. Results preserve input order. It is a
// thin wrapper around EnumerateWith with no per-result callback.
func (e *Enumerator) Enumerate(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration) []EnumResult {
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
func (e *Enumerator) EnumerateWith(ctx context.Context, emails []string, threads int, rateLimit float64, jitter time.Duration, onResult func(EnumResult)) []EnumResult {
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

	// record stores a completed result and, under the same lock, invokes the
	// caller's callback so streamed output is serialized and slice-safe.
	record := func(i int, res EnumResult) {
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
					fmt.Fprintf(os.Stderr, "teams enum: panic checking %s: %v\n%s\n", email, r, debug.Stack())
					record(i, EnumResult{
						Email:  email,
						Exists: ExistenceUnknown,
						Error:  fmt.Errorf("teams enum: panicked: %v", r),
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

			record(i, e.EnumerateOne(ctx, email))
			return nil
		})
	}

	// Discarding g.Wait()'s error is deliberate: worker goroutines never return
	// a non-nil error (per-email failures are encoded in each EnumResult), so the
	// returned error is always nil.
	_ = g.Wait()
	return results
}

// AccountType classifies a Teams MRI: "corporate" (8:orgid:), "consumer"
// (8:live: / Teams For Life), or "" if unknown/empty.
func AccountType(mri string) string {
	switch {
	case strings.HasPrefix(mri, "8:orgid:"):
		return "corporate"
	case strings.HasPrefix(mri, "8:live:"):
		return "consumer"
	default:
		return ""
	}
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
		// Prefer the first corporate (8:orgid:) user. Corporate users are
		// returned regardless of includeTFLUsers, so a corporate match is always
		// a real hit. A consumer-only result (8:live:, "Teams For Life") is noise
		// by default: only treated as a hit when includeConsumer is set.
		chosen := &users[0]
		corporate := false
		for i := range users {
			if AccountType(users[i].MRI) == "corporate" {
				chosen = &users[i]
				corporate = true
				break
			}
		}
		if !corporate && !e.includeConsumer {
			res.Exists = ExistenceNo
			return res
		}
		res.Exists = ExistenceYes
		res.DisplayName = chosen.DisplayName
		res.MRI = chosen.MRI
		res.Type = chosen.Type
		res.TenantID = chosen.TenantID
		res.UserPrincipalName = chosen.UserPrincipalName
		res.ObjectID = chosen.ObjectID
		res.AccountEnabled = chosen.AccountEnabled
		res.CoExistenceMode = chosen.FeatureSettings.CoExistenceMode
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
		if p, ok := e.getPresence(ctx, res.MRI); ok {
			res.Availability = p.Availability
			res.DeviceType = p.DeviceType
			res.SourceNetwork = p.SourceNetwork
			res.OutOfOfficeNote = p.OutOfOfficeNote
		}
	}

	return res
}

// DerivePosture aggregates per-user results into a tenant-level verdict for the
// given domain. The caller derives domain from the target emails. Aggregation
// is defensive: absent signals leave fields at their zero value.
//
// ExternalChatAllowed reflects whether the externalsearchv3 endpoint answered:
// any resolvable user means external/cross-tenant communication is permitted
// ("open"); a 403 with no resolvable users means external search is blocked
// ("blocked"); otherwise the posture is "unknown".
func DerivePosture(domain string, results []EnumResult) TenantPosture {
	p := TenantPosture{
		Domain: domain,
		Total:  len(results),
	}

	for i := range results {
		r := &results[i]

		switch r.Exists {
		case ExistenceYes:
			p.UsersFound++
		case ExistenceBlocked:
			p.Blocked403++
		}

		if strings.EqualFold(r.Type, "Federated") || r.SourceNetwork == "Federated" {
			p.FederatedObserved = true
		}
		if r.Availability != "" {
			p.PresenceVisible = true
		}
		if r.OutOfOfficeNote != "" {
			p.OOOExposed++
		}
		if p.CoExistenceMode == "" && r.CoExistenceMode != "" {
			p.CoExistenceMode = r.CoExistenceMode
		}
	}

	switch {
	case p.UsersFound > 0:
		p.ExternalChatAllowed = "open"
	case p.Blocked403 > 0:
		p.ExternalChatAllowed = "blocked"
	default:
		p.ExternalChatAllowed = "unknown"
	}

	return p
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

// presenceInfo holds the presence-derived signals extracted from a getpresence
// response. All fields are best-effort and stay empty when absent.
type presenceInfo struct {
	Availability    string
	DeviceType      string
	SourceNetwork   string
	OutOfOfficeNote string
}

// getPresence fetches Teams presence for the given MRI. It returns ok=false on
// any failure (best-effort).
func (e *Enumerator) getPresence(ctx context.Context, mri string) (presenceInfo, bool) {
	reqBody, err := json.Marshal([]presenceRequest{{MRI: mri}})
	if err != nil {
		return presenceInfo{}, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.presenceBaseURL, strings.NewReader(string(reqBody)))
	if err != nil {
		return presenceInfo{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token())

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return presenceInfo{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnumBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		return presenceInfo{}, false
	}

	var presences []presenceResponse
	if err := json.Unmarshal(body, &presences); err != nil || len(presences) == 0 {
		return presenceInfo{}, false
	}

	p := presences[0].Presence
	// The OOO note location varies: prefer presence.outOfOfficeNote, fall back to
	// presence.calendarData.outOfOfficeNote.
	ooo := p.OutOfOfficeNote.Message
	if ooo == "" {
		ooo = p.CalendarData.OutOfOfficeNote.Message
	}
	return presenceInfo{
		Availability:    p.Availability,
		DeviceType:      p.DeviceType,
		SourceNetwork:   p.SourceNetwork,
		OutOfOfficeNote: ooo,
	}, true
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
	DisplayName       string `json:"displayName"`
	MRI               string `json:"mri"`
	Type              string `json:"type"` // e.g. "Federated" = external org w/ federation
	TenantID          string `json:"tenantId"`
	UserPrincipalName string `json:"userPrincipalName"`
	ObjectID          string `json:"objectId"`
	AccountEnabled    *bool  `json:"accountEnabled"` // pointer: distinguish absent from false
	IsShortProfile    *bool  `json:"isShortProfile"`
	FeatureSettings   struct {
		CoExistenceMode string `json:"coExistenceMode"`
	} `json:"featureSettings"`
}

type presenceRequest struct {
	MRI string `json:"mri"`
}

type presenceResponse struct {
	Presence struct {
		SourceNetwork string `json:"sourceNetwork"` // "Federated" (open) vs "Unknown" (blocked)
		Availability  string `json:"availability"`
		DeviceType    string `json:"deviceType"`
		// The out-of-office note location varies across responses; parse both
		// shapes and read from whichever is non-empty.
		OutOfOfficeNote struct {
			Message string `json:"message"`
		} `json:"outOfOfficeNote"`
		CalendarData struct {
			OutOfOfficeNote struct {
				Message string `json:"message"`
			} `json:"outOfOfficeNote"`
		} `json:"calendarData"`
	} `json:"presence"`
}
