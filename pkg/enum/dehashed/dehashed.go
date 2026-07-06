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

// Package dehashed provides a client for the DeHashed v2 search API.
// It handles pagination, typed errors, and context cancellation.
//
// Breach-exposed PLAINTEXT passwords (the API "password" field) ARE collected
// and associated with each record. The "hashed_password" field remains absent
// from the unmarshal target and the public types, so hashes are dropped at
// decode time and can never surface in any struct, human output, or JSONL.
package dehashed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// Sentinel errors for use with errors.Is by callers.
var (
	ErrUnauthorized    = errors.New("invalid or missing API key")
	ErrPaymentRequired = errors.New("payment required or out of credits")
	ErrForbidden       = errors.New("access forbidden")
	ErrRateLimited     = errors.New("rate limit exceeded")
)

const (
	baseURL         = "https://api.dehashed.com/v2/search"
	headerAPIKey    = "Dehashed-Api-Key"
	defaultPageSize = 100
	maxResults      = 10000
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// Record is one breach-exposed identity entry for the domain. It carries the
// breach-exposed plaintext Passwords for the record; hashed_password remains
// omitted by design (P0-SCOPE: hashes omitted).
type Record struct {
	ID           string
	Email        []string
	Username     []string
	Name         []string
	IPAddress    []string
	Phone        []string
	Address      []string
	DOB          []string
	Passwords    []string
	Database     string
	ObtainedDate string
}

// DomainResult is the aggregated, de-paginated result for a domain.
type DomainResult struct {
	Domain  string
	Records []Record
	Total   int
	Balance int
}

// RefineOptions controls the refinement pipeline applied to raw breach records
// before output. All filters are opt-in here; the command layer flips them on
// by default and exposes opt-out flags.
type RefineOptions struct {
	Domain            string // searched domain, for CorporateOnly
	CorporateOnly     bool   // keep only records whose email is @Domain
	Dedup             bool   // merge records sharing an email
	ExcludeCombolists bool   // drop combolist/aggregator source DBs
}

// Entry is a refined (optionally merged) output row.
type Entry struct {
	Email     string
	Names     []string
	Usernames []string
	Phones    []string
	Passwords []string // breach-exposed plaintext passwords for this entry
	Databases []string // distinct source DBs contributing to this entry
	Count     int      // number of raw breach records merged into this entry
}

// Refine applies the filtering/merging pipeline to raw breach records and
// returns refined output rows. It is PURE (no I/O) so it is unit-testable.
//
// Pipeline order:
//  1. ExcludeCombolists: drop records whose Database matches the combolist denylist.
//  2. Representative email: with CorporateOnly, the first Email entry ending in
//     "@"+Domain (case-insensitive); record dropped if none match. Without it,
//     the first Email entry (records with no email are kept with Email="").
//  3. Build entries: with Dedup, group by lowercased representative email and
//     union Names/Usernames/Phones/Passwords (deduped, empties dropped) plus
//     distinct Databases, Count = records merged. Without Dedup, one Entry per
//     surviving record. Input order is preserved (emails in first-seen order).
func Refine(records []Record, opts RefineOptions) []Entry {
	domainSuffix := "@" + strings.ToLower(opts.Domain)

	entries := make([]Entry, 0, len(records))
	indexByEmail := make(map[string]int) // lowercased email -> entries index (Dedup only)

	for i := range records {
		r := &records[i]

		if opts.ExcludeCombolists && isCombolist(r.Database) {
			continue
		}

		email, ok := representativeEmail(r.Email, opts.CorporateOnly, domainSuffix)
		if !ok {
			continue
		}

		if opts.Dedup {
			mergeEntry(&entries, indexByEmail, email, r)
			continue
		}

		entries = append(entries, Entry{
			Email:     email,
			Names:     dedupStrings(r.Name),
			Usernames: dedupStrings(r.Username),
			Phones:    dedupStrings(r.Phone),
			Passwords: dedupStrings(r.Passwords),
			Databases: dedupStrings([]string{r.Database}),
			Count:     1,
		})
	}

	return entries
}

// APIError is returned for any non-2xx HTTP status from DeHashed.
type APIError struct {
	StatusCode int
	Details    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("dehashed API error (HTTP %d): %s", e.StatusCode, e.Details)
}

// Unwrap returns the matching sentinel error for 401/402/403/429, nil otherwise.
// This enables errors.Is(err, dehashed.ErrUnauthorized) in callers.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusPaymentRequired:
		return ErrPaymentRequired
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusTooManyRequests:
		return ErrRateLimited
	}
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client holds state for querying the DeHashed v2 search API.
type Client struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	pageSize   int
}

// NewClient builds a DeHashed client. timeout is the per-request HTTP budget.
// pageSize <= 0 falls back to defaultPageSize (100, the API maximum).
func NewClient(apiKey string, timeout time.Duration, pageSize int, proxyURL string) (*Client, error) {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	httpClient, err := enum.NewEnumHTTPClientWithProxy(timeout, proxyURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		apiKey:     apiKey,
		httpClient: httpClient,
		baseURL:    baseURL,
		pageSize:   pageSize,
	}, nil
}

// Search runs a domain search, following pagination until exhausted, and
// returns the aggregated DomainResult. It stops on the first of: an empty page,
// reaching limit (truncating to limit), reaching the known total, the 10,000
// result hard cap, or ctx cancellation. Honors ctx between pages.
func (c *Client) Search(ctx context.Context, domain string, limit int) (*DomainResult, error) {
	result := &DomainResult{Domain: domain}
	query := "domain:" + domain

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		body, err := c.do(ctx, searchRequest{Query: query, Size: c.pageSize, Page: page})
		if err != nil {
			return nil, err
		}

		var resp searchResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decoding dehashed response: %w", err)
		}

		if page == 1 {
			result.Total = resp.Total
			result.Balance = resp.Balance
		}

		for i := range resp.Entries {
			result.Records = append(result.Records, toRecord(&resp.Entries[i]))
		}

		// Termination conditions, checked after accumulating this page.
		if len(resp.Entries) == 0 {
			break
		}
		if limit > 0 && len(result.Records) >= limit {
			result.Records = result.Records[:limit]
			break
		}
		if result.Total > 0 && len(result.Records) >= result.Total {
			break
		}
		if page*c.pageSize >= maxResults {
			break
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// do performs a single POST to the DeHashed search API and returns the bounded
// response body. The API key is sent only in the Dehashed-Api-Key header — it
// never appears in the URL or in any returned error (P0-1 security requirement).
func (c *Client) do(ctx context.Context, body searchRequest) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding dehashed request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building dehashed request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dehashed request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read — reuses enum.ReadResponseBody (P0-3 security requirement).
	respBody, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("reading dehashed response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Details: resp.Status}
	}

	return respBody, nil
}

// combolistDatabases is a curated, conservative denylist of source-database
// substrings identifying aggregator/combolist dumps (not single-breach data).
// Matched case-insensitively as a substring of Record.Database. Kept short on
// purpose: false positives silently drop real breach rows, so only well-known
// combolists/aggregators are listed.
var combolistDatabases = []string{
	"Naz.API",
	"ALIEN TXTBASE",
	"Collection",
	"Combolist",
	"AntiPublic",
	"BreachCompilation",
	"Exploit.in",
	"Cit0day",
	"Pemiblanc",
}

// isCombolist reports whether db matches the combolist denylist (case-insensitive
// substring match).
func isCombolist(db string) bool {
	lower := strings.ToLower(db)
	for _, c := range combolistDatabases {
		if strings.Contains(lower, strings.ToLower(c)) {
			return true
		}
	}
	return false
}

// representativeEmail picks the email used to represent a record. With
// corporateOnly, it returns the first email ending in domainSuffix
// (case-insensitive) and ok=false if none match. Without corporateOnly, it
// returns the first email (or "" with ok=true when the record has no email).
func representativeEmail(emails []string, corporateOnly bool, domainSuffix string) (string, bool) {
	if corporateOnly {
		for _, e := range emails {
			if strings.HasSuffix(strings.ToLower(e), domainSuffix) {
				return e, true
			}
		}
		return "", false
	}
	if len(emails) > 0 {
		return emails[0], true
	}
	return "", true
}

// mergeEntry merges record r into the entry keyed by the lowercased email,
// creating it on first sight (preserving first-seen order in entries).
func mergeEntry(entries *[]Entry, indexByEmail map[string]int, email string, r *Record) {
	key := strings.ToLower(email)
	idx, seen := indexByEmail[key]
	if !seen {
		*entries = append(*entries, Entry{Email: email})
		idx = len(*entries) - 1
		indexByEmail[key] = idx
	}

	e := &(*entries)[idx]
	e.Names = dedupStrings(append(e.Names, r.Name...))
	e.Usernames = dedupStrings(append(e.Usernames, r.Username...))
	e.Phones = dedupStrings(append(e.Phones, r.Phone...))
	e.Passwords = dedupStrings(append(e.Passwords, r.Passwords...))
	e.Databases = dedupStrings(append(e.Databases, r.Database))
	e.Count++
}

// dedupStrings returns the distinct, non-empty values of in, preserving order.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// toRecord converts an API entry to the public Record type. The plaintext
// password field is mapped through; hashed_password is absent from apiEntry and
// Record by design.
func toRecord(e *apiEntry) Record {
	return Record{
		ID:           e.ID,
		Email:        e.Email,
		Username:     e.Username,
		Name:         e.Name,
		IPAddress:    e.IPAddress,
		Phone:        e.Phone,
		Address:      e.Address,
		DOB:          e.DOB,
		Passwords:    e.Password,
		Database:     e.Database,
		ObtainedDate: e.ObtainedDate,
	}
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map to the DeHashed v2 response shape).
// The plaintext "password" field IS mapped and flows into our data model.
// "hashed_password" is DELIBERATELY omitted so hashes are dropped at unmarshal
// and never enter our data model (P0-SCOPE).
// ---------------------------------------------------------------------------

type searchRequest struct {
	Query string `json:"query"`
	Size  int    `json:"size"`
	Page  int    `json:"page"`
}

type searchResponse struct {
	Balance int        `json:"balance"`
	Total   int        `json:"total"`
	Took    string     `json:"took"`
	Entries []apiEntry `json:"entries"`
}

type apiEntry struct {
	ID           string   `json:"id"`
	Email        []string `json:"email"`
	Username     []string `json:"username"`
	Name         []string `json:"name"`
	IPAddress    []string `json:"ip_address"`
	Phone        []string `json:"phone"`
	Address      []string `json:"address"`
	DOB          []string `json:"dob"`
	Password     []string `json:"password"`
	Database     string   `json:"database_name"`
	ObtainedDate string   `json:"obtained_date"`
}
