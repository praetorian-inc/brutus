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
	// v3 batch response: results array with nested jobTitle/company/contactMethods.
	resp := &lushaEnrichResponse{
		RequestID: "req-1",
		Results: []lushaResult{
			{
				FirstName: "Ada",
				LastName:  "Lovelace",
				JobTitle: struct {
					Title string `json:"title"`
				}{Title: "Mathematician"},
				Company: struct {
					Name   string `json:"name"`
					Domain string `json:"domain"`
				}{Name: "Analytical Engine Co"},
				ContactMethods: struct {
					Emails []lushaEmail `json:"emails"`
					Phones []lushaPhone `json:"phones"`
				}{
					Emails: []lushaEmail{
						{Address: "ada@example.com", Type: "professional", Confidence: "high"},
						{Address: "ada.personal@gmail.com", Type: "personal", Confidence: "medium"},
					},
					Phones: []lushaPhone{
						{Number: "+1-555-0100", Type: "direct", DoNotCall: false},
						{Number: "+1-555-0199", Type: "mobile", DoNotCall: true},
					},
				},
			},
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

func TestToContact_EmptyResults(t *testing.T) {
	resp := &lushaEnrichResponse{RequestID: "req-2", Results: nil}
	got := toContact(resp)
	require.NotNil(t, got)
	assert.Empty(t, got.Emails)
	assert.Empty(t, got.Phones)
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
	// Error() must include the HTTP status code.
	err := &APIError{StatusCode: 402, Details: "SECRETKEY-DO-NOT-LEAK"}
	assert.Contains(t, err.Error(), "402")
	// P0-1 security fix: Details must NOT appear in Error() output.
	assert.NotContains(t, err.Error(), "SECRETKEY-DO-NOT-LEAK",
		"APIError.Error() must not include Details (P0-1 key-leak prevention)")
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

		// v3 batch response shape: requestId + results array.
		resp := map[string]interface{}{
			"requestId": "req-test",
			"results": []map[string]interface{}{
				{
					"firstName": "Ada",
					"lastName":  "Lovelace",
					"jobTitle":  map[string]interface{}{"title": "Engineer"},
					"company":   map[string]interface{}{"name": "AnalyticalCo", "domain": ""},
					"contactMethods": map[string]interface{}{
						"emails": []map[string]interface{}{
							{"address": "ada@example.com", "type": "work", "confidence": "95"},
						},
						"phones": []map[string]interface{}{
							{"number": "+1-555-0100", "type": "mobile", "doNotCall": true},
						},
					},
				},
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
	// v3 batch shape: {contacts:[{identity fields}], reveal:["emails","phones"]}.
	tests := []struct {
		name        string
		query       ContactQuery
		reveal      RevealOptions
		wantContact lushaReqContact
		wantReveal  []string
	}{
		{
			name: "name + company, email reveal only",
			query: ContactQuery{
				FirstName:   "Ada",
				LastName:    "Lovelace",
				CompanyName: "AnalyticalCo",
			},
			reveal: RevealOptions{Email: true},
			wantContact: lushaReqContact{
				FirstName:   "Ada",
				LastName:    "Lovelace",
				CompanyName: "AnalyticalCo",
			},
			wantReveal: []string{"emails"},
		},
		{
			name: "name + domain, email+phone reveal",
			query: ContactQuery{
				FirstName:     "Ada",
				LastName:      "Lovelace",
				CompanyDomain: "analytical.example.com",
			},
			reveal: RevealOptions{Email: true, Phone: true},
			wantContact: lushaReqContact{
				FirstName:     "Ada",
				LastName:      "Lovelace",
				CompanyDomain: "analytical.example.com",
			},
			wantReveal: []string{"emails", "phones"},
		},
		{
			name:   "email identity, email reveal",
			query:  ContactQuery{Email: "ada@example.com"},
			reveal: RevealOptions{Email: true},
			wantContact: lushaReqContact{
				Email: "ada@example.com",
			},
			wantReveal: []string{"emails"},
		},
		{
			name:   "linkedin identity, email+phone reveal",
			query:  ContactQuery{LinkedinURL: "https://linkedin.com/in/ada"},
			reveal: RevealOptions{Email: true, Phone: true},
			wantContact: lushaReqContact{
				LinkedinURL: "https://linkedin.com/in/ada",
			},
			wantReveal: []string{"emails", "phones"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEnrichRequest(tc.query, tc.reveal)
			// Must be a batch with exactly one contact.
			require.Len(t, got.Contacts, 1, "batch must have exactly one contact")
			assert.Equal(t, tc.wantContact, got.Contacts[0])
			assert.Equal(t, tc.wantReveal, got.Reveal)
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
		// v3 batch response with empty results array — a "no match", not an error.
		resp := lushaEnrichResponse{RequestID: "req-empty", Results: []lushaResult{}}
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
		resp := lushaEnrichResponse{RequestID: "req-slow", Results: []lushaResult{}}
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
