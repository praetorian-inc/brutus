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

// Contact is the enriched result for one identity.
type Contact struct {
	Name     string
	JobTitle string
	Company  string
	Emails   []EmailEntry
	Phones   []PhoneEntry
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
func NewClient(apiKey string, timeout time.Duration) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: enum.NewEnumHTTPClient(timeout),
		baseURL:    defaultBaseURL,
	}
}

// Enrich resolves one identity to an enriched contact via v3 search-and-enrich.
// A 200 with no datapoints returns a *Contact with empty slices (not an error).
func (c *Client) Enrich(ctx context.Context, q ContactQuery, r RevealOptions) (*Contact, error) {
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
func buildEnrichRequest(q ContactQuery, r RevealOptions) lushaEnrichRequest {
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
		Name:     name,
		JobTitle: r.JobTitle.Title,
		Company:  r.Company.Name,
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
	JobTitle  struct {
		Title string `json:"title"`
	} `json:"jobTitle"`
	Company struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
	} `json:"company"`
	Emails []lushaEmail `json:"emails"`
	Phones []lushaPhone `json:"phones"`
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
