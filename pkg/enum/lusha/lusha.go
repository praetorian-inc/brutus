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

// Package lusha provides a client for the Lusha v3 search-and-enrich API.
// It resolves a single person identity to an enriched contact (emails + phones),
// with typed errors and context cancellation. A single Enrich call spends credits.
package lusha

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
	ErrUnauthorized = errors.New("invalid or missing Lusha API key") // 401
	ErrForbidden    = errors.New("access forbidden")                 // 403
	ErrNoCredits    = errors.New("insufficient Lusha credits")       // 402
	ErrRateLimited  = errors.New("rate limit exceeded")              // 429
	ErrNotFound     = errors.New("no contact found for identity")    // 404
)

const (
	defaultBaseURL = "https://api.lusha.com"
	enrichPath     = "/v3/contacts/search-and-enrich"
	// prospectSearchPath / prospectEnrichPath are the prospecting (roster) API
	// endpoints. Their request/response shapes DIFFER from the single-identity
	// search-and-enrich path above (different field names), so they have their
	// own request/response structs below.
	prospectSearchPath = "/prospecting/contact/search"
	prospectEnrichPath = "/prospecting/contact/enrich"
	// prospectPageSize is the per-page result count for prospecting search. It is
	// held CONSTANT across all pages (API offset = page*size, so a changing size
	// corrupts pagination). The value is within the API's accepted 10-50 range;
	// we use the max to minimize search-page credits.
	prospectPageSize = 50
	// prospectMaxPages bounds collect-all (limit<=0) so a huge org cannot spin
	// indefinitely; 40 pages * 50 = up to 2000 contacts.
	prospectMaxPages = 40
	// headerAPIKey is the Lusha auth header name. UNVERIFIED against a live key
	// (discovery §3 / architecture §11) — isolated here for a single-edit fix.
	headerAPIKey = "api_key"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// ContactQuery carries exactly one identity group (validated at the CLI layer).
type ContactQuery struct {
	FirstName     string
	LastName      string
	CompanyName   string // pairs with FirstName+LastName
	CompanyDomain string // alternative to CompanyName
	Email         string
	LinkedinURL   string
}

// RevealOptions controls which datapoint families are requested (all cost credits).
type RevealOptions struct {
	Email bool
	Phone bool
}

// EmailEntry is one returned email address.
type EmailEntry struct {
	Address    string
	Type       string
	Confidence string
}

// PhoneEntry is one returned phone number. DoNotCall is a compliance signal
// that MUST be surfaced to the operator (P0-DNC) — never hidden.
type PhoneEntry struct {
	Number    string
	Type      string
	DoNotCall bool
}

// EmploymentEntry is one role in the contact's employment history. Lusha's
// previousEmployment carries no dates, so only Organization + Title are
// populated; Current distinguishes the present employer (top-level
// company/jobTitle) from prior roles.
type EmploymentEntry struct {
	Organization string
	Title        string
	Current      bool
}

// Contact is the enriched result for one identity.
type Contact struct {
	Name          string
	FirstName     string
	LastName      string
	JobTitle      string
	Company       string
	CompanyDomain string
	LinkedIn      string
	Departments   []string
	Seniority     string
	Location      string // country
	Emails        []EmailEntry
	Phones        []PhoneEntry
	Employment    []EmploymentEntry
}

// DomainResult is the roster returned by SearchDomain for one company domain.
// Total is the company-wide match count reported by the search API (may exceed
// len(Contacts) when a limit was applied or the page cap was hit). CreditsCharged
// is the accumulated credit cost across every search and enrich call.
type DomainResult struct {
	Domain         string
	Contacts       []Contact
	Total          int
	CreditsCharged int
}

// APIError is returned for any non-2xx HTTP status from Lusha.
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
	return fmt.Sprintf("lusha API error (HTTP %d)", e.StatusCode)
}

// Unwrap maps the status code to its sentinel error, nil otherwise.
// This enables errors.Is(err, lusha.ErrNoCredits) in callers; the *APIError
// itself stays retrievable via errors.As.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusPaymentRequired:
		return ErrNoCredits
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	}
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client holds state for querying the Lusha v3 search-and-enrich API.
type Client struct {
	apiKey     string // api_key header — NEVER logged (P0-1, P0-1b)
	httpClient *http.Client
	baseURL    string
}

// NewClient builds a Lusha client. timeout is the per-request HTTP budget.
// There is no page size: one identity in, one contact out.
func NewClient(apiKey string, timeout time.Duration, proxyURL string) (*Client, error) {
	httpClient, err := enum.NewEnumHTTPClientWithProxy(timeout, proxyURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		apiKey:     apiKey,
		httpClient: httpClient,
		baseURL:    defaultBaseURL,
	}, nil
}

// Enrich resolves one identity to an enriched contact via v3 search-and-enrich.
// A 200 with no datapoints returns a *Contact with empty slices (not an error).
func (c *Client) Enrich(ctx context.Context, q *ContactQuery, r RevealOptions) (*Contact, error) {
	body := buildEnrichRequest(q, r)
	raw, err := c.do(ctx, http.MethodPost, enrichPath, body)
	if err != nil {
		return nil, err
	}

	var resp lushaEnrichResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding lusha response: %w", err)
	}
	return toContact(&resp), nil
}

// SearchDomain enumerates a company roster by domain via the prospecting API.
// It paginates POST /prospecting/contact/search (company-domain filter), then
// enriches each search page's contacts via POST /prospecting/contact/enrich
// using that page's requestId. Set limit>0 to bound the roster (and credit
// spend); limit<=0 collects ALL matches, bounded by prospectMaxPages.
//
// Total is taken from the first page's totalResults. CreditsCharged accumulates
// every search and enrich call's billing.creditsCharged. ctx is honored between
// pages. NO printing — all data and cost are returned as values.
func (c *Client) SearchDomain(ctx context.Context, domain string, limit int) (*DomainResult, error) {
	result := &DomainResult{Domain: domain}

	for page := 0; page < prospectMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// The search page size MUST stay constant across pages: the API offset is
		// page*size, so shrinking size on a later page corrupts the offset and
		// duplicates/skips contacts. Spend is bounded on the enrich side below by
		// only enriching `remaining` contactIds per page (search is ~1 credit/page
		// regardless of size). prospectPageSize is already within the API's 10-50
		// range, so no clamping is needed.
		remaining := 0
		if limit > 0 {
			remaining = limit - len(result.Contacts)
			if remaining <= 0 {
				break
			}
		}

		search, err := c.searchProspectPage(ctx, domain, page, prospectPageSize)
		if err != nil {
			return nil, err
		}
		result.CreditsCharged += search.Billing.CreditsCharged
		if page == 0 {
			result.Total = search.TotalResults
		}
		if len(search.Data) == 0 {
			break
		}

		// Enrich only as many contacts as we still need, so a small --limit does
		// not pay enrich credits for the over-fetched page tail.
		entries := search.Data
		if limit > 0 && remaining < len(entries) {
			entries = entries[:remaining]
		}
		ids := make([]string, 0, len(entries))
		for _, d := range entries {
			ids = append(ids, d.ContactID)
		}

		enriched, credits, err := c.enrichProspectPage(ctx, search.RequestID, ids)
		if err != nil {
			return nil, err
		}
		result.CreditsCharged += credits
		result.Contacts = append(result.Contacts, enriched...)

		if limit > 0 && len(result.Contacts) >= limit {
			break
		}
		if result.Total > 0 && len(result.Contacts) >= result.Total {
			break
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// do performs a single JSON request. It sets the api_key header inline (never
// in the URL), reads the body via the bounded reader (P0-3), and maps non-2xx
// statuses to *APIError. The key, header, body, and URL are NEVER logged
// (P0-1); full-request dumping is forbidden (P0-1c) because the auth header
// would be captured.
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding lusha request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building lusha request: %w", err)
	}
	req.Header.Set(headerAPIKey, c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lusha request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read — reuses enum.ReadResponseBody (P0-3 security requirement).
	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("reading lusha response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Extract details from the error envelope if decodable, else resp.Status.
		// Details is only ever resp.Status or server-envelope text — never the
		// request body or key. The classifier (CLI layer) does not echo it.
		details := resp.Status
		var env lushaErrorEnvelope
		if json.Unmarshal(raw, &env) == nil && env.Message != "" {
			details = env.Message
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Details: details}
	}

	return raw, nil
}

// buildEnrichRequest maps the identity group + reveal flags to the v3 batch
// request shape: a single contact plus a reveal token list. The reveal token
// values ("emails"/"phones") are UNVERIFIED against a live key — they are
// isolated here so a single edit corrects any mismatch without touching control
// flow.
func buildEnrichRequest(q *ContactQuery, r RevealOptions) lushaEnrichRequest {
	var reveal []string
	if r.Email {
		reveal = append(reveal, "emails")
	}
	if r.Phone {
		reveal = append(reveal, "phones")
	}
	return lushaEnrichRequest{
		Contacts: []lushaReqContact{{
			FirstName:     q.FirstName,
			LastName:      q.LastName,
			CompanyName:   q.CompanyName,
			CompanyDomain: q.CompanyDomain,
			Email:         q.Email,
			LinkedinURL:   q.LinkedinURL,
		}},
		Reveal: reveal,
	}
}

// toContact converts the v3 batch response into the public Contact type,
// reading the single Results[0] entry and preserving the per-phone DoNotCall
// flag (P0-DNC). An empty Results yields an empty *Contact (no error).
func toContact(resp *lushaEnrichResponse) *Contact {
	if len(resp.Results) == 0 {
		return &Contact{}
	}
	r := resp.Results[0]

	name := r.FirstName
	if r.LastName != "" {
		if name != "" {
			name += " "
		}
		name += r.LastName
	}

	c := &Contact{
		Name:          name,
		FirstName:     r.FirstName,
		LastName:      r.LastName,
		JobTitle:      r.JobTitle.Title,
		Company:       r.Company.Name,
		CompanyDomain: r.Company.Domain,
		LinkedIn:      r.SocialLinks.Linkedin,
		Departments:   r.JobTitle.Departments,
		Seniority:     r.JobTitle.Seniority,
		Location:      r.Location.Country,
	}
	// Employment = current role (from top-level company/jobTitle) followed by
	// prior roles. Lusha previousEmployment lacks dates, so Current is the only
	// temporal signal.
	c.Employment = append(c.Employment, EmploymentEntry{
		Organization: r.Company.Name,
		Title:        r.JobTitle.Title,
		Current:      true,
	})
	for _, pe := range r.PreviousEmployment {
		c.Employment = append(c.Employment, EmploymentEntry{
			Organization: pe.Company.Name,
			Title:        pe.JobTitle.Title,
			Current:      false,
		})
	}
	// emails/phones are top-level on each result; map explicitly because the
	// vendor field names differ from the public type (e.g. email -> Address).
	for _, e := range r.Emails {
		c.Emails = append(c.Emails, EmailEntry{
			Address:    e.Email,
			Type:       e.Type,
			Confidence: e.Confidence,
		})
	}
	for _, p := range r.Phones {
		c.Phones = append(c.Phones, PhoneEntry{
			Number:    p.Number,
			Type:      p.Type,
			DoNotCall: p.DoNotCall,
		})
	}
	return c
}

// searchProspectPage requests one prospecting search page filtered by company
// domain and decodes the response.
func (c *Client) searchProspectPage(ctx context.Context, domain string, page, size int) (*prospectSearchResponse, error) {
	body := prospectSearchRequest{}
	body.Pages.Page = page
	body.Pages.Size = size
	body.Filters.Companies.Include.Domains = []string{domain}

	raw, err := c.do(ctx, http.MethodPost, prospectSearchPath, body)
	if err != nil {
		return nil, err
	}
	var resp prospectSearchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding lusha prospecting search response: %w", err)
	}
	return &resp, nil
}

// enrichProspectPage enriches one search page's contactIds (tied to its
// requestId) and maps each successful result to a public Contact. It returns
// the contacts and the credits charged for the call.
func (c *Client) enrichProspectPage(ctx context.Context, requestID string, ids []string) ([]Contact, int, error) {
	if len(ids) == 0 {
		return nil, 0, nil
	}

	raw, err := c.do(ctx, http.MethodPost, prospectEnrichPath, prospectEnrichRequest{
		RequestID:  requestID,
		ContactIDs: ids,
	})
	if err != nil {
		return nil, 0, err
	}
	var resp prospectEnrichResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, 0, fmt.Errorf("decoding lusha prospecting enrich response: %w", err)
	}

	contacts := make([]Contact, 0, len(resp.Contacts))
	for i := range resp.Contacts {
		ec := &resp.Contacts[i]
		if !ec.IsSuccess {
			continue
		}
		contacts = append(contacts, toProspectContact(&ec.Data))
	}
	return contacts, resp.CreditsCharged, nil
}

// toProspectContact maps one enriched prospecting contact to the public Contact
// type. Field names differ from the single-identity path (e.g. emailAddresses,
// phoneNumbers, seniority[].value), so the mapping is explicit. DoNotCall is
// preserved per phone (P0-DNC).
func toProspectContact(d *prospectEnrichData) Contact {
	name := d.FullName
	if name == "" {
		name = d.FirstName
		if d.LastName != "" {
			if name != "" {
				name += " "
			}
			name += d.LastName
		}
	}

	seniority := make([]string, 0, len(d.Seniority))
	for _, s := range d.Seniority {
		if s.Value != "" {
			seniority = append(seniority, s.Value)
		}
	}

	c := Contact{
		Name:        name,
		FirstName:   d.FirstName,
		LastName:    d.LastName,
		JobTitle:    d.JobTitle,
		Company:     d.CompanyName,
		LinkedIn:    d.SocialLinks.Linkedin,
		Departments: d.Departments,
		Seniority:   strings.Join(seniority, ", "),
		Location:    d.Location.Country,
	}
	for _, e := range d.EmailAddresses {
		c.Emails = append(c.Emails, EmailEntry{
			Address:    e.Email,
			Type:       e.EmailType,
			Confidence: e.EmailConfidence,
		})
	}
	for _, p := range d.PhoneNumbers {
		c.Phones = append(c.Phones, PhoneEntry{
			Number:    p.Number,
			Type:      p.PhoneType,
			DoNotCall: p.DoNotCall,
		})
	}
	c.Employment = append(c.Employment, EmploymentEntry{
		Organization: d.CompanyName,
		Title:        d.JobTitle,
		Current:      true,
	})
	return c
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported) — verified against live API 2026-06-26.
// Architecture §11: isolated here so a single edit corrects a live mismatch
// without touching control flow. httptest tests use controlled payloads and
// pass regardless of live-schema correctness.
// ---------------------------------------------------------------------------

// lushaEnrichRequest is the v3 search-and-enrich request body. The real v3
// POST /v3/contacts/search-and-enrich uses a BATCH shape: a contacts array
// (we send a single contact) plus a reveal token list.
type lushaEnrichRequest struct {
	Contacts []lushaReqContact `json:"contacts"`
	// Reveal is the datapoint-family token list, e.g. ["emails","phones"].
	// NOTE: the exact reveal token values ("emails"/"phones") remain UNVERIFIED
	// against a live key (residual live-schema risk flagged in review).
	Reveal []string `json:"reveal"`
}

// lushaReqContact is one identity in the batch. Exactly one identity group is
// set: firstName+lastName+(companyName|companyDomain) | email | linkedinUrl.
type lushaReqContact struct {
	FirstName     string `json:"firstName,omitempty"`
	LastName      string `json:"lastName,omitempty"`
	CompanyName   string `json:"companyName,omitempty"`
	CompanyDomain string `json:"companyDomain,omitempty"`
	Email         string `json:"email,omitempty"`
	LinkedinURL   string `json:"linkedinUrl,omitempty"`
}

// lushaEnrichResponse is the v3 search-and-enrich response body. results is a
// batch parallel to the request contacts; we send one contact so read
// Results[0].
type lushaEnrichResponse struct {
	RequestID string        `json:"requestId"`
	Results   []lushaResult `json:"results"`
}

// lushaResult is one enriched contact from the batch. emails and phones are
// TOP-LEVEL arrays on each result (there is no contactMethods wrapper).
type lushaResult struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	FullName  string `json:"fullName"`
	JobTitle  struct {
		Title       string   `json:"title"`
		Departments []string `json:"departments"`
		Seniority   string   `json:"seniority"`
	} `json:"jobTitle"`
	Company struct {
		Name     string `json:"name"`
		Domain   string `json:"domain"`
		Industry string `json:"industry"`
	} `json:"company"`
	Location           lushaLocation         `json:"location"`
	SocialLinks        lushaSocialLinks      `json:"socialLinks"`
	PreviousEmployment []lushaPrevEmployment `json:"previousEmployment"`
	Emails             []lushaEmail          `json:"emails"`
	Phones             []lushaPhone          `json:"phones"`
}

// lushaSocialLinks holds the contact's social profile URLs. Only linkedin is
// mapped today.
type lushaSocialLinks struct {
	Linkedin string `json:"linkedin"`
}

// lushaLocation holds geographic fields. Only country is mapped today.
type lushaLocation struct {
	Country string `json:"country"`
}

// lushaPrevEmployment is one prior role. The live sample carried no explicit
// start/end dates, so only organization + title are captured.
type lushaPrevEmployment struct {
	Company struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
	} `json:"company"`
	JobTitle struct {
		Title string `json:"title"`
	} `json:"jobTitle"`
}

type lushaEmail struct {
	Email      string `json:"email"`
	Type       string `json:"type"`
	Confidence string `json:"confidence"` // letter grade, e.g. "A+"
	UpdateDate string `json:"updateDate"`
}

type lushaPhone struct {
	Number     string `json:"number"`
	Type       string `json:"type"`
	DoNotCall  bool   `json:"doNotCall"`
	UpdateDate string `json:"updateDate"`
}

// lushaErrorEnvelope is the (UNVERIFIED) shape of a v3 error body. Only its
// Message is surfaced as APIError.Details (never the key or request body).
type lushaErrorEnvelope struct {
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// Prospecting (roster) JSON-mapping structs — field names DIFFER from the
// single-identity search-and-enrich structs above. Verified live 2026-06-26.
// ---------------------------------------------------------------------------

// prospectSearchRequest filters prospecting search by company domain.
type prospectSearchRequest struct {
	Pages struct {
		Page int `json:"page"`
		Size int `json:"size"`
	} `json:"pages"`
	Filters struct {
		Companies struct {
			Include struct {
				Domains []string `json:"domains"`
			} `json:"include"`
		} `json:"companies"`
	} `json:"filters"`
}

// prospectSearchResponse is one prospecting search page. requestId ties this
// page's contactIds to a subsequent enrich call.
type prospectSearchResponse struct {
	RequestID    string                `json:"requestId"`
	CurrentPage  int                   `json:"currentPage"`
	TotalResults int                   `json:"totalResults"`
	Data         []prospectSearchEntry `json:"data"`
	Billing      prospectSearchBilling `json:"billing"`
}

// prospectSearchEntry is one contact stub from a search page; only contactId is
// needed to enrich (full data comes from the enrich call).
type prospectSearchEntry struct {
	ContactID string `json:"contactId"`
}

type prospectSearchBilling struct {
	CreditsCharged  int `json:"creditsCharged"`
	ResultsReturned int `json:"resultsReturned"`
}

// prospectEnrichRequest enriches contactIds tied to a search page's requestId.
type prospectEnrichRequest struct {
	RequestID  string   `json:"requestId"`
	ContactIDs []string `json:"contactIds"`
}

// prospectEnrichResponse is the enrich result batch plus the credits charged.
type prospectEnrichResponse struct {
	RequestID      string                  `json:"requestId"`
	Contacts       []prospectEnrichContact `json:"contacts"`
	CreditsCharged int                     `json:"creditsCharged"`
}

// prospectEnrichContact wraps one enriched contact; data is only valid when
// isSuccess is true.
type prospectEnrichContact struct {
	ID        string             `json:"id"`
	IsSuccess bool               `json:"isSuccess"`
	Data      prospectEnrichData `json:"data"`
}

// prospectEnrichData is the enriched payload. Field names (emailAddresses,
// phoneNumbers, seniority[].value) differ from the single-identity result.
type prospectEnrichData struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	FullName    string `json:"fullName"`
	JobTitle    string `json:"jobTitle"`
	CompanyName string `json:"companyName"`
	Location    struct {
		Country   string `json:"country"`
		Continent string `json:"continent"`
	} `json:"location"`
	EmailAddresses []struct {
		Email           string `json:"email"`
		EmailType       string `json:"emailType"`
		EmailConfidence string `json:"emailConfidence"`
	} `json:"emailAddresses"`
	PhoneNumbers []struct {
		Number    string `json:"number"`
		PhoneType string `json:"phoneType"`
		DoNotCall bool   `json:"doNotCall"`
	} `json:"phoneNumbers"`
	SocialLinks struct {
		Linkedin string `json:"linkedin"`
		XURL     string `json:"xUrl"`
	} `json:"socialLinks"`
	Departments []string `json:"departments"`
	Seniority   []struct {
		ID    int    `json:"id"`
		Value string `json:"value"`
	} `json:"seniority"`
}
