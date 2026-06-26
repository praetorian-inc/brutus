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

// Package apollo provides a client for the Apollo.io people search and match
// APIs. It performs free domain people-discovery (no PII) and, on request,
// opt-in email reveal (consumes credits). It handles pagination, typed errors,
// and context cancellation, mirroring the Hunter.io client pattern.
package apollo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// Sentinel errors for use with errors.Is by callers.
var (
	ErrUnauthorized = errors.New("invalid or missing Apollo API key")      // 401
	ErrForbidden    = errors.New("access forbidden (plan or permissions)") // 403
	ErrBadRequest   = errors.New("invalid request parameters")             // 422
	ErrRateLimited  = errors.New("rate limit exceeded")                    // 429
)

const (
	defaultBaseURL  = "https://api.apollo.io"
	searchPath      = "/api/v1/mixed_people/api_search"
	matchPath       = "/api/v1/people/match"
	headerAPIKey    = "X-Api-Key"
	defaultPageSize = 100
	// maxPages is a hard safety cap (Apollo documents 100/page x 500 pages = 50k).
	maxPages = 500
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// Person is one discovered contact for the domain. Email/EmailStatus are empty
// until RevealEmails runs (opt-in, consumes credits).
type Person struct {
	// From people-search (FREE, no PII).
	ID           string
	FirstName    string
	LastName     string
	Name         string
	Title        string
	Seniority    string
	Department   string
	Organization string

	// From people/match (CREDITS, PII) — empty unless reveal ran.
	Email       string
	EmailStatus string
	Revealed    bool
}

// DomainResult is the aggregated, de-paginated result for a domain.
type DomainResult struct {
	Domain   string
	People   []Person
	Total    int  // pagination.total_entries
	Revealed bool // true if RevealEmails ran (any credits spent)
}

// APIError is returned for any non-2xx HTTP status from Apollo.
type APIError struct {
	StatusCode int
	// Details holds server-derived text (resp.Status or error-envelope message)
	// for internal/debug use. It is deliberately EXCLUDED from Error() so a
	// caller that logs the error cannot leak echoed keys/PII (P0-1).
	Details string
}

// Error returns ONLY status-derived text. It does NOT include Details, which
// could echo vendor response content back into logs (P0-1).
func (e *APIError) Error() string {
	return fmt.Sprintf("apollo API error (HTTP %d)", e.StatusCode)
}

// Unwrap maps status → sentinel (401/403/422/429), nil otherwise. This enables
// errors.Is(err, apollo.ErrUnauthorized) in callers while the *APIError remains
// retrievable via errors.As.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusUnprocessableEntity:
		return ErrBadRequest
	case http.StatusTooManyRequests:
		return ErrRateLimited
	}
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client holds state for querying the Apollo people search and match APIs.
type Client struct {
	apiKey     string // X-Api-Key — NEVER logged (P0-1)
	httpClient *http.Client
	baseURL    string
	pageSize   int // people-search per_page; <=0 => defaultPageSize
}

// NewClient builds an Apollo client. timeout is the per-request HTTP budget.
// pageSize <= 0 falls back to defaultPageSize.
func NewClient(apiKey string, timeout time.Duration, pageSize int) *Client {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	return &Client{
		apiKey:     apiKey,
		httpClient: enum.NewEnumHTTPClient(timeout),
		baseURL:    defaultBaseURL,
		pageSize:   pageSize,
	}
}

// SearchPeople paginates people-search for domain (optionally filtered by
// titles), accumulating up to limit people. Phase 1 is FREE and returns no PII.
// Honors ctx cancellation between pages.
func (c *Client) SearchPeople(ctx context.Context, domain string, titles []string, limit int) (*DomainResult, error) {
	result := &DomainResult{Domain: domain}
	page := 1

	for {
		people, total, err := c.searchPage(ctx, domain, titles, page)
		if err != nil {
			// Return the partial result alongside the error so the caller still
			// has the contacts discovered on earlier pages.
			return result, err
		}
		if page == 1 {
			result.Total = total
		}

		result.People = append(result.People, people...)

		fetched := len(people)
		if fetched == 0 { // empty page
			break
		}
		if limit > 0 && len(result.People) >= limit { // user cap (truncate)
			result.People = result.People[:limit]
			break
		}
		if fetched < c.pageSize { // short final page
			break
		}
		if result.Total > 0 && len(result.People) >= result.Total { // known total
			break
		}
		if page >= maxPages { // hard safety cap
			break
		}
		if err := ctx.Err(); err != nil { // cancellation
			return result, err
		}
		page++
	}

	return result, nil
}

// RevealEmails enriches the already-discovered people in result with emails via
// people/match, in place, serially. Consumes credits. Skips people without an
// id. Sets Email/EmailStatus/Revealed per person (Revealed=true even when the
// returned email is empty — partial-result honesty) and sets result.Revealed=true
// on the FIRST successful match so spent credits are reflected even if a later
// match fails. Surfaces the first error (no partial swallow), leaving
// already-merged emails intact.
func (c *Client) RevealEmails(ctx context.Context, result *DomainResult) error {
	for i := range result.People {
		p := &result.People[i]
		if p.ID == "" { // can't match without an id
			continue
		}
		email, status, err := c.matchPerson(ctx, p.ID)
		if err != nil {
			// On error, return it but leave the emails merged so far intact;
			// result.Revealed is already true if any earlier reveal succeeded.
			return err
		}
		p.Email, p.EmailStatus, p.Revealed = email, status, true
		// Mark the aggregate as revealed on the FIRST successful match — credits
		// have been spent, so the partial result must reflect that even if a
		// later match fails.
		result.Revealed = true
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// searchPage performs a single people-search POST and returns the mapped people
// plus the reported total_entries.
func (c *Client) searchPage(ctx context.Context, domain string, titles []string, page int) (people []Person, total int, err error) {
	reqBody := apolloSearchRequest{
		OrganizationDomains: []string{domain},
		PersonTitles:        titles,
		Page:                page,
		PerPage:             c.pageSize,
	}
	body, err := c.do(ctx, http.MethodPost, searchPath, reqBody)
	if err != nil {
		return nil, 0, err
	}

	var resp apolloSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("decoding apollo search response: %w", err)
	}

	out := make([]Person, len(resp.People))
	for i := range resp.People {
		out[i] = toPerson(&resp.People[i])
	}
	return out, resp.Pagination.TotalEntries, nil
}

// matchPerson reveals the email for a single Apollo person id. Consumes credits.
func (c *Client) matchPerson(ctx context.Context, id string) (email, status string, err error) {
	reqBody := apolloMatchRequest{ID: id, RevealPersonalEmails: true}
	body, err := c.do(ctx, http.MethodPost, matchPath, reqBody)
	if err != nil {
		return "", "", err
	}

	var resp apolloMatchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", fmt.Errorf("decoding apollo match response: %w", err)
	}
	return resp.Person.Email, resp.Person.EmailStatus, nil
}

// do is the single P0-1/P0-3 choke point: it JSON-encodes body, sets the
// X-Api-Key header and Content-Type, issues the request, reads the response via
// the bounded enum.ReadResponseBody (P0-3), and maps any non-2xx status to an
// *APIError. It NEVER logs the key, the header, the body, or the URL (P0-1), and
// NEVER uses httputil.Dump* (which would capture the X-Api-Key header) (P0-1c).
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding apollo request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building apollo request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apollo request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read — reuses enum.ReadResponseBody (P0-3).
	respBody, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("reading apollo response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Extract details from the error envelope if decodable, else resp.Status.
		details := resp.Status
		var errResp apolloErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.message() != "" {
			details = errResp.message()
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Details: details}
	}

	return respBody, nil
}

// toPerson converts the API person struct to the public Person type. Search
// fields only; PII (Email/EmailStatus) is left empty and Revealed=false.
func toPerson(p *apolloPerson) Person {
	dept := ""
	if len(p.Departments) > 0 {
		dept = p.Departments[0]
	}
	return Person{
		ID:           p.ID,
		FirstName:    p.FirstName,
		LastName:     p.LastName,
		Name:         p.Name,
		Title:        p.Title,
		Seniority:    p.Seniority,
		Department:   dept,
		Organization: p.Organization.Name,
	}
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map to the Apollo API shapes).
//
// NOTE (UNVERIFIED): the request/response field names and endpoint paths below
// are derived from Apollo docs (architecture §7) and have NOT been verified
// against a live key. They are intentionally isolated here so a single edit
// corrects any mismatch without touching control flow. httptest tests use
// controlled payloads and pass regardless of live-schema correctness.
// ---------------------------------------------------------------------------

type apolloSearchRequest struct {
	OrganizationDomains []string `json:"q_organization_domains_list,omitempty"`
	PersonTitles        []string `json:"person_titles,omitempty"`
	Page                int      `json:"page"`
	PerPage             int      `json:"per_page"`
}

type apolloSearchResponse struct {
	People     []apolloPerson   `json:"people"`
	Pagination apolloPagination `json:"pagination"`
}

type apolloPagination struct {
	Page         int `json:"page"`
	PerPage      int `json:"per_page"`
	TotalEntries int `json:"total_entries"`
	TotalPages   int `json:"total_pages"`
}

type apolloMatchRequest struct {
	ID                   string `json:"id"`
	RevealPersonalEmails bool   `json:"reveal_personal_emails"`
}

type apolloMatchResponse struct {
	Person apolloPerson `json:"person"`
}

type apolloPerson struct {
	ID           string             `json:"id"`
	FirstName    string             `json:"first_name"`
	LastName     string             `json:"last_name"`
	Name         string             `json:"name"`
	Title        string             `json:"title"`
	Seniority    string             `json:"seniority"`
	Departments  []string           `json:"departments"`
	Organization apolloOrganization `json:"organization"`
	Email        string             `json:"email"`
	EmailStatus  string             `json:"email_status"`
}

type apolloOrganization struct {
	Name string `json:"name"`
}

// apolloErrorResponse models Apollo's error envelope. Apollo has used both
// "error" and "message" keys across endpoints; check both. (UNVERIFIED — §7.)
type apolloErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (e apolloErrorResponse) message() string {
	if e.Error != "" {
		return e.Error
	}
	return e.Message
}
