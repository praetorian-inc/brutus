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

// Person is one discovered contact for the domain. The enrichment-only fields
// are empty until EnrichByIDs/RevealEmails runs (consumes credits).
type Person struct {
	// From people-search (FREE, thin — last_name is obfuscated/empty here).
	ID           string
	FirstName    string
	LastName     string
	Name         string
	Title        string
	Seniority    string
	Department   string
	Organization string

	// Availability signals from people-search (FREE, no credits): whether a
	// verified email / direct phone could be revealed by enrichment. HasPhone is
	// true only when the search tier reports a definite "Yes" (a "Maybe" requires
	// a separate bulk_match request and is treated as not-available here).
	HasEmail bool
	HasPhone bool

	// From people/match (CREDITS, PII) — empty unless enrichment ran.
	Email       string
	EmailStatus string
	LinkedinURL string
	Twitter     string
	Departments []string
	City        string
	State       string
	Country     string
	Employment  []EmploymentEntry
	Revealed    bool
}

// EmploymentEntry is one raw entry from a person's employment_history. Raw
// pass-through — no derived fields (e.g. tenure) are computed.
type EmploymentEntry struct {
	Organization string
	Title        string
	StartDate    string
	EndDate      string
	Current      bool
}

// DomainResult is the aggregated, de-paginated result for a domain.
type DomainResult struct {
	Domain         string
	People         []Person
	Total          int  // pagination.total_entries
	Revealed       bool // true if enrichment ran (any credits spent)
	CreditsCharged int  // count of people enriched = Apollo credits spent
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
		baseURL:    defaultBaseURL,
		pageSize:   pageSize,
	}, nil
}

// Discover paginates people-search for domain (optionally filtered by titles),
// accumulating up to limit people. This is the cheap discovery step: it is FREE,
// returns no PII (only availability flags HasEmail/HasPhone), and consumes no
// credits. Honors ctx cancellation between pages.
func (c *Client) Discover(ctx context.Context, domain string, titles []string, limit int) (*DomainResult, error) {
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

// EnrichByIDs is the selective enrichment step: it reveals the full matched
// record (linkedin_url, verified email, departments, seniority, employment,
// etc.) for each given Apollo person id via people/match, serially. This is what
// the SaaS UI calls on the operator's per-person selection. CONSUMES CREDITS —
// one per id. Skips empty ids. Returns the enriched Person records (each with
// Revealed=true) in id order, omitting any skipped (empty) ids. Surfaces the
// first match error, returning the records enriched so far alongside it so the
// caller still has — and is accountable for — the credits already spent. Honors
// ctx cancellation between matches.
func (c *Client) EnrichByIDs(ctx context.Context, ids []string) ([]Person, error) {
	enriched := make([]Person, 0, len(ids))
	for _, id := range ids {
		if id == "" { // can't match without an id
			continue
		}
		matched, err := c.matchPerson(ctx, id)
		if err != nil {
			// Return the records enriched so far alongside the error — those
			// credits are already spent, so the caller must still see them.
			return enriched, err
		}
		matched.ID = id // preserve the requested id (match echo may differ/omit)
		matched.Revealed = true
		enriched = append(enriched, matched)
		if err := ctx.Err(); err != nil {
			return enriched, err
		}
	}
	return enriched, nil
}

// RevealEmails is a convenience that enriches ALL discovered people in result,
// in place. It is the CLI --enrich (manual full-pull) path, NOT the default. It
// delegates to EnrichByIDs over the result's ids and merges the enriched fields
// (un-obfuscated last name, email/status, LinkedIn/Twitter, seniority,
// departments, location, employment history) back onto each person by id.
// CONSUMES CREDITS — one per enriched person, recorded in result.CreditsCharged.
// Sets result.Revealed=true if any person was enriched (so spent credits are
// reflected even if a later match fails). Surfaces the first error (no partial
// swallow), leaving already-merged records intact.
func (c *Client) RevealEmails(ctx context.Context, result *DomainResult) error {
	// Deduplicate ids before enriching: pagination can surface the same person
	// twice, and EnrichByIDs spends one credit per id — enriching a duplicate would
	// burn a credit for a record already revealed. Empty ids are dropped here too
	// (EnrichByIDs also skips them). The merge-by-id loop below still fans a single
	// enriched record back onto every row sharing that id.
	ids := make([]string, 0, len(result.People))
	seen := make(map[string]struct{}, len(result.People))
	for i := range result.People {
		id := result.People[i].ID
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	enriched, err := c.EnrichByIDs(ctx, ids)

	// Merge whatever was enriched (even on partial error) back by id, and record
	// the credits spent so the partial result stays honest.
	byID := make(map[string]*Person, len(enriched))
	for i := range enriched {
		byID[enriched[i].ID] = &enriched[i]
	}
	for i := range result.People {
		if m, ok := byID[result.People[i].ID]; ok {
			mergeReveal(&result.People[i], m)
		}
	}
	result.CreditsCharged = len(enriched)
	if len(enriched) > 0 {
		result.Revealed = true
	}

	return err
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
		out[i] = resp.People[i].toPerson()
	}
	return out, resp.TotalEntries, nil
}

// matchPerson reveals the full record for a single Apollo person id via
// people/match. Consumes credits. Returns the mapped Person (search + reveal
// fields), which the caller merges onto the discovered person.
func (c *Client) matchPerson(ctx context.Context, id string) (Person, error) {
	reqBody := apolloMatchRequest{ID: id, RevealPersonalEmails: true}
	body, err := c.do(ctx, http.MethodPost, matchPath, reqBody)
	if err != nil {
		return Person{}, err
	}

	var resp apolloMatchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Person{}, fmt.Errorf("decoding apollo match response: %w", err)
	}
	return resp.Person.toPerson(), nil
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

type apolloPerson struct {
	ID           string             `json:"id"`
	FirstName    string             `json:"first_name"`
	LastName     string             `json:"last_name"`
	Name         string             `json:"name"`
	Title        string             `json:"title"`
	Seniority    string             `json:"seniority"`
	Departments  []string           `json:"departments"`
	Organization apolloOrganization `json:"organization"`
	// Availability flags from people-search (no credits). has_email is a bool;
	// has_direct_phone is a STRING ("Yes" / "Maybe: ...") — verified live
	// 2026-06-26, hence the string type and the =="Yes" mapping in toPerson.
	HasEmail          bool                    `json:"has_email"`
	HasDirectPhone    string                  `json:"has_direct_phone"`
	Email             string                  `json:"email"`
	EmailStatus       string                  `json:"email_status"`
	LinkedinURL       string                  `json:"linkedin_url"`
	TwitterURL        string                  `json:"twitter_url"`
	City              string                  `json:"city"`
	State             string                  `json:"state"`
	Country           string                  `json:"country"`
	EmploymentHistory []apolloEmploymentEntry `json:"employment_history"`
}

// toPerson converts the API person struct to the public Person type, mapping
// every field present in the payload. The search response is thin (reveal-only
// fields are null/empty and map to zero values); the match response populates
// the full record. Revealed is NOT set here — the caller owns that flag.
func (p *apolloPerson) toPerson() Person {
	dept := ""
	if len(p.Departments) > 0 {
		dept = p.Departments[0]
	}
	employment := make([]EmploymentEntry, len(p.EmploymentHistory))
	for i := range p.EmploymentHistory {
		h := &p.EmploymentHistory[i]
		employment[i] = EmploymentEntry{
			Organization: h.OrganizationName,
			Title:        h.Title,
			StartDate:    h.StartDate,
			EndDate:      h.EndDate,
			Current:      h.Current,
		}
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
		HasEmail:     p.HasEmail,
		HasPhone:     p.HasDirectPhone == "Yes",
		Email:        p.Email,
		EmailStatus:  p.EmailStatus,
		LinkedinURL:  p.LinkedinURL,
		Twitter:      p.TwitterURL,
		Departments:  p.Departments,
		City:         p.City,
		State:        p.State,
		Country:      p.Country,
		Employment:   employment,
	}
}

// mergeReveal merges the enriched fields from a people/match record onto the
// discovered person, overwriting the obfuscated/empty search-tier last name and
// filling in the reveal-only fields. Search-tier identity fields already on p
// (ID, Name, Title, Organization) are left intact.
func mergeReveal(p, m *Person) {
	p.LastName = m.LastName
	p.Email = m.Email
	p.EmailStatus = m.EmailStatus
	p.LinkedinURL = m.LinkedinURL
	p.Twitter = m.Twitter
	p.Seniority = m.Seniority
	p.Departments = m.Departments
	p.City = m.City
	p.State = m.State
	p.Country = m.Country
	p.Employment = m.Employment
	p.Revealed = true
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map to the Apollo API shapes).
//
// NOTE: verified against live API 2026-06-26 (total_entries top-level;
// last_name masked pre-reveal). The request/response field names and endpoint
// paths below are intentionally isolated here so a single edit corrects any
// mismatch without touching control flow. httptest tests use controlled
// payloads and pass regardless of live-schema correctness.
// ---------------------------------------------------------------------------

type apolloSearchRequest struct {
	OrganizationDomains []string `json:"q_organization_domains_list,omitempty"`
	PersonTitles        []string `json:"person_titles,omitempty"`
	Page                int      `json:"page"`
	PerPage             int      `json:"per_page"`
}

// apolloSearchResponse maps the mixed_people/api_search body. total_entries is a
// TOP-LEVEL field (the pagination object is null at the credit-free tier).
type apolloSearchResponse struct {
	People       []apolloPerson `json:"people"`
	TotalEntries int            `json:"total_entries"`
}

type apolloMatchRequest struct {
	ID                   string `json:"id"`
	RevealPersonalEmails bool   `json:"reveal_personal_emails"`
}

type apolloMatchResponse struct {
	Person apolloPerson `json:"person"`
}

type apolloEmploymentEntry struct {
	OrganizationName string `json:"organization_name"`
	Title            string `json:"title"`
	StartDate        string `json:"start_date"`
	EndDate          string `json:"end_date"`
	Current          bool   `json:"current"`
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
