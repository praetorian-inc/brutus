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
// Credentials are intentionally NOT collected: the API "password" and
// "hashed_password" fields are absent from the unmarshal target and the
// public Record type, so they are dropped at decode time and can never
// surface in any struct, human output, or JSONL.
package dehashed

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

// Record is one breach-exposed identity entry for the domain. It deliberately
// carries NO password / hashed_password fields (P0-SCOPE: credentials omitted).
type Record struct {
	ID           string
	Email        []string
	Username     []string
	Name         []string
	IPAddress    []string
	Phone        []string
	Address      []string
	DOB          []string
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
func NewClient(apiKey string, timeout time.Duration, pageSize int) *Client {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	return &Client{
		apiKey:     apiKey,
		httpClient: enum.NewEnumHTTPClient(timeout),
		baseURL:    baseURL,
		pageSize:   pageSize,
	}
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

// toRecord converts an API entry to the public Record type. Credential fields
// (password / hashed_password) are absent from apiEntry and Record by design.
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
		Database:     e.Database,
		ObtainedDate: e.ObtainedDate,
	}
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map to the DeHashed v2 response shape).
// password / hashed_password are DELIBERATELY omitted so they are dropped at
// unmarshal and never enter our data model (P0-SCOPE).
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
	Database     string   `json:"database_name"`
	ObtainedDate string   `json:"obtained_date"`
}
