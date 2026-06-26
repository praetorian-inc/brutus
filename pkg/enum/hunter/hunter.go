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

// Package hunter provides a client for the Hunter.io Domain Search API.
// It handles pagination, typed errors, and context cancellation.
package hunter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// Sentinel errors for use with errors.Is by callers.
var (
	ErrUnauthorized = errors.New("invalid or missing API key")
	ErrRateLimited  = errors.New("rate limit exceeded")
	ErrLegalReasons = errors.New("unavailable for legal reasons")
	// ErrPlanLimited signals the Hunter plan's result cap was hit mid-pagination.
	// Search treats this as a soft stop and returns the results collected so far.
	ErrPlanLimited = errors.New("plan result cap reached")
)

// planLimitMarker is the stable substring Hunter returns in the 400 error
// details when the account's plan result cap is exceeded, e.g.:
// "The search results are limited to 10 email addresses on your current plan."
const planLimitMarker = "results are limited to"

const (
	defaultBaseURL  = "https://api.hunter.io/v2/domain-search"
	defaultPageSize = 100
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// Person is one discovered contact for the domain.
type Person struct {
	Email      string
	FirstName  string
	LastName   string
	Position   string
	Seniority  string
	Department string
	Phone      string
	LinkedIn   string
	Twitter    string
	Confidence int
	Type       string
	Sources    []string
}

// DomainResult is the aggregated, de-paginated result for a domain.
type DomainResult struct {
	Domain       string
	Organization string
	People       []Person
	Total        int
	// Truncated is true when the plan result cap was hit mid-pagination and the
	// returned People are a partial set (Total reflects the full count available).
	Truncated bool
}

// APIError is returned for any non-200 HTTP status from Hunter.io.
type APIError struct {
	StatusCode int
	Details    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("hunter API error (HTTP %d): %s", e.StatusCode, e.Details)
}

// Unwrap returns the matching sentinel error for 401/429/451, or ErrPlanLimited
// for the specific 400 plan-cap response, nil otherwise. This enables
// errors.Is(err, hunter.ErrUnauthorized) (and ErrPlanLimited) in callers.
func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusUnavailableForLegalReasons:
		return ErrLegalReasons
	case http.StatusBadRequest:
		// Only the plan-cap 400 maps to a sentinel; other 400s stay generic.
		if strings.Contains(e.Details, planLimitMarker) {
			return ErrPlanLimited
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client holds state for querying the Hunter.io Domain Search API.
type Client struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	pageSize   int
}

// NewClient builds a Hunter client. timeout is the per-request HTTP budget.
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

// Search runs Domain Search for domain, following pagination until exhausted,
// and returns the aggregated DomainResult. Honors ctx cancellation between pages.
func (c *Client) Search(ctx context.Context, domain string) (*DomainResult, error) {
	offset := 0
	result := &DomainResult{Domain: domain}

	for {
		page, err := c.fetchPage(ctx, domain, offset)
		if err != nil {
			// Plan result cap is a soft stop: return what we collected so far.
			// Other errors (auth, rate limit, etc.) remain fatal.
			if errors.Is(err, ErrPlanLimited) {
				result.Truncated = true
				break
			}
			return nil, err
		}

		if offset == 0 {
			result.Organization = page.Data.Organization
			result.Total = page.Meta.Results
		}

		for i := range page.Data.Emails {
			result.People = append(result.People, toPerson(&page.Data.Emails[i]))
		}

		fetched := len(page.Data.Emails)
		offset += fetched

		// Termination: empty page, short final page, or reached known total.
		if fetched == 0 {
			break
		}
		if fetched < c.pageSize {
			break
		}
		if result.Total > 0 && offset >= result.Total {
			break
		}

		// Honor context cancellation before issuing the next request.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// fetchPage performs a single paginated GET request to the Hunter.io API.
// The api_key is embedded in the query string per the Hunter API contract.
// The full URL is never logged to prevent key leakage (P0-1 security requirement).
func (c *Client) fetchPage(ctx context.Context, domain string, offset int) (*apiResponse, error) {
	// Build query string — api_key goes here per Hunter's spec.
	q := url.Values{
		"domain":  {domain},
		"api_key": {c.apiKey},
		"limit":   {strconv.Itoa(c.pageSize)},
		"offset":  {strconv.Itoa(offset)},
	}
	rawURL := c.baseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building hunter request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hunter request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read — reuses enum.ReadResponseBody (P0-3 security requirement).
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return nil, fmt.Errorf("reading hunter response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Extract details from error envelope if present.
		var errResp apiResponse
		details := resp.Status
		if json.Unmarshal(body, &errResp) == nil && len(errResp.Errors) > 0 {
			details = errResp.Errors[0].Details
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Details: details}
	}

	var page apiResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decoding hunter response: %w", err)
	}
	return &page, nil
}

// toPerson converts the API email struct to the public Person type.
func toPerson(e *apiEmail) Person {
	sources := make([]string, len(e.Sources))
	for i, s := range e.Sources {
		sources[i] = s.URI
	}
	if len(sources) == 0 {
		sources = nil
	}
	return Person{
		Email:      e.Value,
		FirstName:  e.FirstName,
		LastName:   e.LastName,
		Position:   e.Position,
		Seniority:  e.Seniority,
		Department: e.Department,
		Phone:      e.Phone,
		LinkedIn:   e.LinkedIn,
		Twitter:    e.Twitter,
		Confidence: e.Confidence,
		Type:       e.Type,
		Sources:    sources,
	}
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map exactly to Hunter API response shape)
// ---------------------------------------------------------------------------

type apiResponse struct {
	Data   apiData    `json:"data"`
	Meta   apiMeta    `json:"meta"`
	Errors []apiError `json:"errors"`
}

type apiData struct {
	Domain       string     `json:"domain"`
	Organization string     `json:"organization"`
	Emails       []apiEmail `json:"emails"`
}

type apiEmail struct {
	Value      string      `json:"value"`
	Type       string      `json:"type"`
	Confidence int         `json:"confidence"`
	FirstName  string      `json:"first_name"`
	LastName   string      `json:"last_name"`
	Position   string      `json:"position"`
	Seniority  string      `json:"seniority"`
	Department string      `json:"department"`
	Phone      string      `json:"phone_number"`
	LinkedIn   string      `json:"linkedin"`
	Twitter    string      `json:"twitter"`
	Sources    []apiSource `json:"sources"`
}

type apiSource struct {
	URI string `json:"uri"`
}

type apiMeta struct {
	Results int `json:"results"`
	Limit   int `json:"limit"`
	Offset  int `json:"offset"`
}

type apiError struct {
	ID      string `json:"id"`
	Code    int    `json:"code"`
	Details string `json:"details"`
}
