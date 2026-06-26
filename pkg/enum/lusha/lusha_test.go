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

package lusha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient overrides baseURL for httptest usage.
func newTestClient(baseURL string) *Client {
	c := NewClient("testkey", 5*time.Second)
	c.baseURL = baseURL
	return c
}

// ---------------------------------------------------------------------------
// T101: toContact + APIError/Unwrap
// ---------------------------------------------------------------------------

func TestToContact(t *testing.T) {
	resp := &lushaEnrichResponse{
		Name:     "Ada Lovelace",
		JobTitle: "Mathematician",
		Company:  "Analytical Engine Co",
		EmailAddresses: []lushaEmail{
			{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			{Address: "ada.personal@gmail.com", Type: "personal", Confidence: "medium"},
		},
		PhoneNumbers: []lushaPhone{
			{Number: "+1-555-0100", Type: "direct", DoNotCall: false},
			{Number: "+1-555-0199", Type: "mobile", DoNotCall: true},
		},
	}
	got := toContact(resp)
	assert.Equal(t, "Ada Lovelace", got.Name)
	assert.Equal(t, "Mathematician", got.JobTitle)
	assert.Equal(t, "Analytical Engine Co", got.Company)

	require.Len(t, got.Emails, 2)
	assert.Equal(t, "ada@example.com", got.Emails[0].Address)
	assert.Equal(t, "professional", got.Emails[0].Type)
	assert.Equal(t, "high", got.Emails[0].Confidence)
	assert.Equal(t, "ada.personal@gmail.com", got.Emails[1].Address)

	require.Len(t, got.Phones, 2)
	assert.Equal(t, "+1-555-0100", got.Phones[0].Number)
	assert.Equal(t, "direct", got.Phones[0].Type)
	assert.False(t, got.Phones[0].DoNotCall)

	assert.Equal(t, "+1-555-0199", got.Phones[1].Number)
	assert.Equal(t, "mobile", got.Phones[1].Type)
	// DoNotCall MUST be preserved (P0-DNC compliance requirement).
	assert.True(t, got.Phones[1].DoNotCall, "DoNotCall flag must be preserved")
}

func TestAPIError_Unwrap(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		sentinel   error
		wantIs     bool
	}{
		{"401 maps to ErrUnauthorized", http.StatusUnauthorized, ErrUnauthorized, true},
		{"402 maps to ErrNoCredits", http.StatusPaymentRequired, ErrNoCredits, true},
		{"403 maps to ErrForbidden", http.StatusForbidden, ErrForbidden, true},
		{"404 maps to ErrNotFound", http.StatusNotFound, ErrNotFound, true},
		{"429 maps to ErrRateLimited", http.StatusTooManyRequests, ErrRateLimited, true},
		{"500 does not map to ErrUnauthorized", http.StatusInternalServerError, ErrUnauthorized, false},
		{"500 does not map to ErrNoCredits", http.StatusInternalServerError, ErrNoCredits, false},
		{"500 does not map to ErrRateLimited", http.StatusInternalServerError, ErrRateLimited, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &APIError{StatusCode: tc.statusCode, Details: "test"}
			assert.Equal(t, tc.wantIs, errors.Is(err, tc.sentinel))
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 402, Details: "no credits remaining"}
	assert.Contains(t, err.Error(), "402")
	assert.Contains(t, err.Error(), "no credits remaining")
}

// ---------------------------------------------------------------------------
// T102: Enrich success + auth header + request body
// ---------------------------------------------------------------------------

func TestEnrich_Success(t *testing.T) {
	var capturedReqBody []byte
	var capturedAPIKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get(headerAPIKey)

		// api_key must NOT appear in the URL query string.
		assert.NotContains(t, r.URL.RawQuery, "api_key",
			"api_key must not appear in URL")

		body, _ := io.ReadAll(r.Body)
		capturedReqBody = body

		resp := lushaEnrichResponse{
			Name:     "Ada Lovelace",
			JobTitle: "Engineer",
			Company:  "AnalyticalCo",
			EmailAddresses: []lushaEmail{
				{Address: "ada@example.com", Type: "professional", Confidence: "high"},
			},
			PhoneNumbers: []lushaPhone{
				{Number: "+1-555-0100", Type: "direct", DoNotCall: true},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	q := ContactQuery{
		FirstName:   "Ada",
		LastName:    "Lovelace",
		CompanyName: "AnalyticalCo",
	}
	r := RevealOptions{Email: true, Phone: true}
	contact, err := c.Enrich(context.Background(), q, r)
	require.NoError(t, err)

	// API key set as header, not in URL.
	assert.Equal(t, "testkey", capturedAPIKey)

	// Request body must carry the identity.
	assert.Contains(t, string(capturedReqBody), "Ada",
		"request body must contain identity fields")

	// Contact fields mapped correctly.
	require.NotNil(t, contact)
	require.Len(t, contact.Emails, 1)
	assert.Equal(t, "ada@example.com", contact.Emails[0].Address)

	require.Len(t, contact.Phones, 1)
	assert.Equal(t, "+1-555-0100", contact.Phones[0].Number)
	assert.True(t, contact.Phones[0].DoNotCall, "DNC flag must be preserved")
}

func TestBuildEnrichRequest(t *testing.T) {
	tests := []struct {
		name    string
		query   ContactQuery
		reveal  RevealOptions
		wantReq lushaEnrichRequest
	}{
		{
			name: "name + company",
			query: ContactQuery{
				FirstName:   "Ada",
				LastName:    "Lovelace",
				CompanyName: "AnalyticalCo",
			},
			reveal: RevealOptions{Email: true},
			wantReq: lushaEnrichRequest{
				FirstName:    "Ada",
				LastName:     "Lovelace",
				CompanyName:  "AnalyticalCo",
				RevealEmails: true,
			},
		},
		{
			name: "name + domain",
			query: ContactQuery{
				FirstName:     "Ada",
				LastName:      "Lovelace",
				CompanyDomain: "analytical.example.com",
			},
			reveal: RevealOptions{Email: true, Phone: true},
			wantReq: lushaEnrichRequest{
				FirstName:     "Ada",
				LastName:      "Lovelace",
				CompanyDomain: "analytical.example.com",
				RevealEmails:  true,
				RevealPhones:  true,
			},
		},
		{
			name:   "email only",
			query:  ContactQuery{Email: "ada@example.com"},
			reveal: RevealOptions{Email: true},
			wantReq: lushaEnrichRequest{
				Email:        "ada@example.com",
				RevealEmails: true,
			},
		},
		{
			name:   "linkedin only",
			query:  ContactQuery{LinkedinURL: "https://linkedin.com/in/ada"},
			reveal: RevealOptions{Email: true, Phone: true},
			wantReq: lushaEnrichRequest{
				LinkedinURL:  "https://linkedin.com/in/ada",
				RevealEmails: true,
				RevealPhones: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEnrichRequest(tc.query, tc.reveal)
			assert.Equal(t, tc.wantReq, got)
		})
	}
}

func TestEnrich_401ErrUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid API key"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.Enrich(context.Background(), ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))
}

func TestEnrich_402ErrNoCredits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"message":"insufficient credits"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.Enrich(context.Background(), ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoCredits))

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusPaymentRequired, apiErr.StatusCode)
}

func TestEnrich_429ErrRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.Enrich(context.Background(), ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited))
}

func TestEnrich_EmptyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 with empty arrays — a "no match" that is not an error.
		resp := lushaEnrichResponse{}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	contact, err := c.Enrich(context.Background(), ContactQuery{Email: "nobody@example.com"}, RevealOptions{Email: true})
	require.NoError(t, err, "empty 200 must not return an error")
	require.NotNil(t, contact)
	assert.Empty(t, contact.Emails)
	assert.Empty(t, contact.Phones)
}

func TestEnrich_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.Enrich(context.Background(), ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding lusha response")
}

func TestEnrich_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow server: sleep longer than the ctx deadline.
		time.Sleep(300 * time.Millisecond)
		resp := lushaEnrichResponse{}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Enrich(ctx, ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err, "context cancellation must produce an error")
}
