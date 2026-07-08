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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient overrides baseURL for httptest usage.
func newTestClient(baseURL string) *Client {
	c, _ := NewClient("testkey", 5*time.Second, "") // Empty proxy never errors.
	c.baseURL = baseURL
	return c
}

// ---------------------------------------------------------------------------
// T101: toContact + APIError/Unwrap
// ---------------------------------------------------------------------------

func TestToContact(t *testing.T) {
	// v3 batch response: results array with top-level emails/phones on each result
	// (no contactMethods wrapper). Verified against live API 2026-06-26.
	resp := &lushaEnrichResponse{
		RequestID: "req-1",
		Results: []lushaResult{
			{
				FirstName: "Ada",
				LastName:  "Lovelace",
				JobTitle: struct {
					Title       string   `json:"title"`
					Departments []string `json:"departments"`
					Seniority   string   `json:"seniority"`
				}{
					Title:       "Mathematician",
					Departments: []string{"Research"},
					Seniority:   "director",
				},
				Company: struct {
					Name     string `json:"name"`
					Domain   string `json:"domain"`
					Industry string `json:"industry"`
				}{
					Name:     "Analytical Engine Co",
					Domain:   "analytical.example.com",
					Industry: "Technology",
				},
				Location: lushaLocation{Country: "United Kingdom"},
				SocialLinks: lushaSocialLinks{
					Linkedin: "https://linkedin.com/in/ada",
				},
				PreviousEmployment: []lushaPrevEmployment{
					{
						Company: struct {
							Name   string `json:"name"`
							Domain string `json:"domain"`
						}{Name: "Paramount"},
						JobTitle: struct {
							Title string `json:"title"`
						}{Title: "Director"},
					},
				},
				Emails: []lushaEmail{
					{Email: "ada@example.com", Type: "professional", Confidence: "A+", UpdateDate: "2026-06-26"},
					{Email: "ada.personal@gmail.com", Type: "personal", Confidence: "B", UpdateDate: "2026-06-26"},
				},
				Phones: []lushaPhone{
					{Number: "+1-555-0100", Type: "direct", DoNotCall: false, UpdateDate: "2026-06-26"},
					{Number: "+1-555-0199", Type: "mobile", DoNotCall: true, UpdateDate: "2026-06-26"},
				},
			},
		},
	}
	got := toContact(resp)
	assert.Equal(t, "Ada Lovelace", got.Name)
	assert.Equal(t, "Ada", got.FirstName)
	assert.Equal(t, "Lovelace", got.LastName)
	assert.Equal(t, "Mathematician", got.JobTitle)
	assert.Equal(t, "Analytical Engine Co", got.Company)
	assert.Equal(t, "analytical.example.com", got.CompanyDomain)
	assert.Equal(t, "https://linkedin.com/in/ada", got.LinkedIn)
	assert.Equal(t, []string{"Research"}, got.Departments)
	assert.Equal(t, "director", got.Seniority)
	assert.Equal(t, "United Kingdom", got.Location)

	// Employment: current role first (Current:true), then previous (Current:false).
	require.Len(t, got.Employment, 2, "expected current + 1 previous employment entry")
	assert.Equal(t, "Analytical Engine Co", got.Employment[0].Organization)
	assert.Equal(t, "Mathematician", got.Employment[0].Title)
	assert.True(t, got.Employment[0].Current)
	assert.Equal(t, "Paramount", got.Employment[1].Organization)
	assert.Equal(t, "Director", got.Employment[1].Title)
	assert.False(t, got.Employment[1].Current)

	require.Len(t, got.Emails, 2)
	// lushaEmail.Email maps to EmailEntry.Address
	assert.Equal(t, "ada@example.com", got.Emails[0].Address)
	assert.Equal(t, "professional", got.Emails[0].Type)
	assert.Equal(t, "A+", got.Emails[0].Confidence) // string grade, not numeric
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
		// emails/phones are TOP-LEVEL on each result (no contactMethods wrapper).
		// email key (not address); confidence is a letter grade string.
		// Verified against live API 2026-06-26.
		resp := map[string]interface{}{
			"requestId": "req-test",
			"results": []map[string]interface{}{
				{
					"firstName": "Rodrigo",
					"lastName":  "Alvear",
					"jobTitle":  map[string]interface{}{"title": "Director"},
					"company":   map[string]interface{}{"name": "Chilevision", "domain": "chilevision.cl"},
					"emails": []map[string]interface{}{
						{"email": "r@chilevision.cl", "type": "work", "confidence": "A+", "updateDate": "2026-06-26"},
					},
					"phones": []map[string]interface{}{
						{"number": "+56 9 8220 8875", "type": "phone", "doNotCall": false, "updateDate": "2026-06-26"},
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
	contact, err := c.Enrich(context.Background(), &q, r)
	require.NoError(t, err)

	// API key set as header, not in URL.
	assert.Equal(t, "testkey", capturedAPIKey)

	// Request body must carry the identity.
	assert.Contains(t, string(capturedReqBody), "Ada",
		"request body must contain identity fields")

	// Contact fields mapped correctly (live-verified shape, 2026-06-26).
	require.NotNil(t, contact)
	require.Len(t, contact.Emails, 1)
	assert.Equal(t, "r@chilevision.cl", contact.Emails[0].Address)
	assert.Equal(t, "work", contact.Emails[0].Type)
	assert.Equal(t, "A+", contact.Emails[0].Confidence)

	require.Len(t, contact.Phones, 1)
	assert.Equal(t, "+56 9 8220 8875", contact.Phones[0].Number)
	assert.False(t, contact.Phones[0].DoNotCall, "DNC flag must be preserved as false")
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
			got := buildEnrichRequest(&tc.query, tc.reveal)
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
	_, err := c.Enrich(context.Background(), &ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
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
	_, err := c.Enrich(context.Background(), &ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
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
	_, err := c.Enrich(context.Background(), &ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
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
	contact, err := c.Enrich(context.Background(), &ContactQuery{Email: "nobody@example.com"}, RevealOptions{Email: true})
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
	_, err := c.Enrich(context.Background(), &ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
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

	_, err := c.Enrich(ctx, &ContactQuery{Email: "a@b.com"}, RevealOptions{Email: true})
	require.Error(t, err, "context cancellation must produce an error")
}

// ---------------------------------------------------------------------------
// T106: SearchDomain — prospecting search + enrich pagination
// ---------------------------------------------------------------------------

// prospectSearchBody mirrors the fields our handler needs to inspect.
type prospectSearchBody struct {
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

type prospectEnrichBody struct {
	RequestID  string   `json:"requestId"`
	ContactIDs []string `json:"contactIds"`
}

func TestSearchDomain_Success(t *testing.T) {
	var capturedSearch, capturedEnrich []byte
	var capturedAPIKey string

	searchResp := map[string]interface{}{
		"requestId":    "r1",
		"currentPage":  0,
		"pageLength":   2,
		"totalResults": 2,
		"data": []map[string]interface{}{
			{"contactId": "c1"},
			{"contactId": "c2"},
		},
		"billing": map[string]interface{}{
			"creditsCharged":  1,
			"resultsReturned": 2,
		},
	}
	enrichResp := map[string]interface{}{
		"requestId": "r1",
		"contacts": []map[string]interface{}{
			{
				"id":        "c1",
				"isSuccess": true,
				"data": map[string]interface{}{
					"fullName":    "Bruna White",
					"jobTitle":    "Assistant Director",
					"companyName": "Fox",
					"location":    map[string]interface{}{"country": "United States"},
					"emailAddresses": []map[string]interface{}{
						{"email": "bruna.white@fox.com", "emailType": "work", "emailConfidence": "A+"},
					},
					"phoneNumbers": []map[string]interface{}{
						{"number": "+1 818", "phoneType": "phone", "doNotCall": true},
					},
					"socialLinks": map[string]interface{}{
						"linkedin": "https://linkedin.com/in/bw",
					},
					"departments": []string{"Other"},
					"seniority": []map[string]interface{}{
						{"id": 6, "value": "director"},
					},
				},
			},
			{
				"id":        "c2",
				"isSuccess": true,
				"data": map[string]interface{}{
					"fullName":       "Steve R",
					"jobTitle":       "Director",
					"companyName":    "Fox",
					"emailAddresses": []interface{}{},
					"phoneNumbers":   []interface{}{},
					"departments":    []string{},
					"seniority":      []interface{}{},
				},
			},
		},
		"creditsCharged": 2,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get(headerAPIKey)
		// api_key must NOT appear in the URL query string (P0-1).
		assert.NotContains(t, r.URL.RawQuery, "api_key",
			"api_key must not appear in URL")

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		switch r.URL.Path {
		case prospectSearchPath:
			capturedSearch = body
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(searchResp))
		case prospectEnrichPath:
			capturedEnrich = body
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(enrichResp))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result, err := c.SearchDomain(context.Background(), "fox.com", 0)
	require.NoError(t, err)

	// ---- result shape ----
	assert.Equal(t, 2, result.Total, "Total must equal totalResults from search page")
	require.Len(t, result.Contacts, 2)

	// Credits: 1 for search plus 2 for enrich, totaling 3
	assert.Equal(t, 3, result.CreditsCharged, "CreditsCharged must sum search+enrich billing")

	// ---- Bruna White (first contact) ----
	bruna := result.Contacts[0]
	assert.Equal(t, "Bruna White", bruna.Name)
	assert.Equal(t, "Assistant Director", bruna.JobTitle)
	assert.Equal(t, "Fox", bruna.Company)
	assert.Equal(t, "United States", bruna.Location)
	assert.Equal(t, "https://linkedin.com/in/bw", bruna.LinkedIn)
	assert.Equal(t, []string{"Other"}, bruna.Departments)
	assert.Equal(t, "director", bruna.Seniority)

	require.Len(t, bruna.Emails, 1, "Bruna must have 1 email")
	assert.Equal(t, "bruna.white@fox.com", bruna.Emails[0].Address)
	assert.Equal(t, "A+", bruna.Emails[0].Confidence)

	require.Len(t, bruna.Phones, 1, "Bruna must have 1 phone")
	assert.True(t, bruna.Phones[0].DoNotCall, "DoNotCall flag must be preserved (P0-DNC)")

	// ---- api_key header ----
	assert.Equal(t, "testkey", capturedAPIKey, "api_key header must be sent")

	// ---- search request body carries domain filter ----
	var sb prospectSearchBody
	require.NoError(t, json.Unmarshal(capturedSearch, &sb))
	require.Contains(t, sb.Filters.Companies.Include.Domains, "fox.com",
		"search request must carry the domain filter")

	// ---- enrich request carries correct requestId + contactIds ----
	var eb prospectEnrichBody
	require.NoError(t, json.Unmarshal(capturedEnrich, &eb))
	assert.Equal(t, "r1", eb.RequestID,
		"enrich request must use the page's requestId")
	assert.ElementsMatch(t, []string{"c1", "c2"}, eb.ContactIDs,
		"enrich request must carry the page's contactIds")
}

func TestSearchDomain_Pagination(t *testing.T) {
	// makeEnrichContacts builds a prospect enrich response body.
	makeEnrichContacts := func(reqID string, names []string) map[string]interface{} {
		contacts := make([]map[string]interface{}, 0, len(names))
		for i, name := range names {
			contacts = append(contacts, map[string]interface{}{
				"id":        strings.ToLower(strings.ReplaceAll(name, " ", "")) + fmt.Sprintf("-%d", i),
				"isSuccess": true,
				"data": map[string]interface{}{
					"fullName":       name,
					"emailAddresses": []interface{}{},
					"phoneNumbers":   []interface{}{},
					"departments":    []string{},
					"seniority":      []interface{}{},
				},
			})
		}
		return map[string]interface{}{
			"requestId":      reqID,
			"contacts":       contacts,
			"creditsCharged": len(names),
		}
	}

	// makeContactIDs generates n unique contactId strings for a given page.
	makeContactIDs := func(page, n int) []map[string]interface{} {
		entries := make([]map[string]interface{}, n)
		for i := 0; i < n; i++ {
			entries[i] = map[string]interface{}{
				"contactId": fmt.Sprintf("page%d-contact%d", page, i),
			}
		}
		return entries
	}

	// newSmallPaginationServer creates a server with page0=2 contacts, page1=1.
	// Used by collect-all and limit=1 subtests.
	newSmallPaginationServer := func(t *testing.T) *httptest.Server {
		t.Helper()
		searchCallCount := 0
		page0Search := map[string]interface{}{
			"requestId":    "page0-req",
			"currentPage":  0,
			"totalResults": 3,
			"data": []map[string]interface{}{
				{"contactId": "p0c1"},
				{"contactId": "p0c2"},
			},
			"billing": map[string]interface{}{"creditsCharged": 1, "resultsReturned": 2},
		}
		page1Search := map[string]interface{}{
			"requestId":    "page1-req",
			"currentPage":  1,
			"totalResults": 3,
			"data": []map[string]interface{}{
				{"contactId": "p1c1"},
			},
			"billing": map[string]interface{}{"creditsCharged": 1, "resultsReturned": 1},
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch r.URL.Path {
			case prospectSearchPath:
				w.Header().Set("Content-Type", "application/json")
				if searchCallCount == 0 {
					require.NoError(t, json.NewEncoder(w).Encode(page0Search))
				} else {
					require.NoError(t, json.NewEncoder(w).Encode(page1Search))
				}
				searchCallCount++
			case prospectEnrichPath:
				var eb prospectEnrichBody
				require.NoError(t, json.Unmarshal(body, &eb))
				w.Header().Set("Content-Type", "application/json")
				allNames := map[string][]string{
					"page0-req": {"Alice P", "Bob P"},
					"page1-req": {"Carol P"},
				}
				names, ok := allNames[eb.RequestID]
				if !ok {
					http.Error(w, "unknown requestId", http.StatusBadRequest)
					return
				}
				if len(eb.ContactIDs) < len(names) {
					names = names[:len(eb.ContactIDs)]
				}
				require.NoError(t, json.NewEncoder(w).Encode(makeEnrichContacts(eb.RequestID, names)))
			default:
				http.NotFound(w, r)
			}
		}))
	}

	// CRITICAL: limit=75 spanning page0 (50 contacts) + page1 (25 contacts).
	// This is the regression test for the pagination bug:
	//   Bug: pages.size shrank on page 1 (e.g., to 25), corrupting the offset
	//        (page1*25 != page1*50) and causing dupes/skips.
	//   Fix: pages.size is CONSTANT (prospectPageSize=50) across ALL pages.
	t.Run("limit=75 spans two pages with CONSTANT search size (regression: no dupes)", func(t *testing.T) {
		// Track captured search bodies so we can assert pages.size is constant.
		// The httptest server is called sequentially by SearchDomain, so no
		// locking is needed; a plain slice is sufficient.
		var searchBodies [][]byte

		// Page 0: 50 distinct contactIds.  Page 1: 50 distinct contactIds.
		// With limit=75, enrich should request all 50 from page 0, then only 25
		// from page 1 (remaining = 75 - 50 = 25).
		page0ContactIDs := makeContactIDs(0, 50)
		page1ContactIDs := makeContactIDs(1, 50)

		// Build corresponding enriched names for each page.
		page0Names := make([]string, 50)
		for i := 0; i < 50; i++ {
			page0Names[i] = fmt.Sprintf("Page0Contact%d", i)
		}
		page1Names := make([]string, 50)
		for i := 0; i < 50; i++ {
			page1Names[i] = fmt.Sprintf("Page1Contact%d", i)
		}

		searchCallCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			switch r.URL.Path {
			case prospectSearchPath:
				// Capture the raw search body for size assertion.
				bodyCopy := make([]byte, len(body))
				copy(bodyCopy, body)
				searchBodies = append(searchBodies, bodyCopy)

				w.Header().Set("Content-Type", "application/json")
				if searchCallCount == 0 {
					require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
						"requestId":    "page0-75-req",
						"currentPage":  0,
						"totalResults": 100, // pretend 100 total
						"data":         page0ContactIDs,
						"billing":      map[string]interface{}{"creditsCharged": 1, "resultsReturned": 50},
					}))
				} else {
					require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
						"requestId":    "page1-75-req",
						"currentPage":  1,
						"totalResults": 100,
						"data":         page1ContactIDs,
						"billing":      map[string]interface{}{"creditsCharged": 1, "resultsReturned": 50},
					}))
				}
				searchCallCount++

			case prospectEnrichPath:
				var eb prospectEnrichBody
				require.NoError(t, json.Unmarshal(body, &eb))
				w.Header().Set("Content-Type", "application/json")

				var names []string
				switch eb.RequestID {
				case "page0-75-req":
					names = page0Names[:len(eb.ContactIDs)]
				case "page1-75-req":
					names = page1Names[:len(eb.ContactIDs)]
				default:
					http.Error(w, "unknown requestId", http.StatusBadRequest)
					return
				}
				require.NoError(t, json.NewEncoder(w).Encode(makeEnrichContacts(eb.RequestID, names)))

			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()

		c := newTestClient(srv.URL)
		result, err := c.SearchDomain(context.Background(), "bigcorp.com", 75)
		require.NoError(t, err)

		// --- Regression assertion: exactly 75 contacts, no duplicates ---
		require.Len(t, result.Contacts, 75,
			"limit=75 must return exactly 75 contacts spanning both pages")

		// Collect all names returned; verify no duplicates.
		seen := make(map[string]int)
		for _, c := range result.Contacts {
			seen[c.Name]++
		}
		for name, count := range seen {
			assert.Equal(t, 1, count,
				"duplicate contact detected: %q appeared %d times (pagination bug)", name, count)
		}

		// The first 50 must come from page 0, the last 25 from page 1.
		for i := 0; i < 50; i++ {
			assert.Equal(t, fmt.Sprintf("Page0Contact%d", i), result.Contacts[i].Name,
				"contact %d must be from page 0", i)
		}
		for i := 50; i < 75; i++ {
			assert.Equal(t, fmt.Sprintf("Page1Contact%d", i-50), result.Contacts[i].Name,
				"contact %d must be from page 1", i)
		}

		// --- Key invariant: pages.size must be CONSTANT across both search calls ---
		// Both captured search bodies must have the same pages.size value (prospectPageSize=50).
		require.Len(t, searchBodies, 2, "exactly 2 search requests must have been made")
		type pagesBlock struct {
			Pages struct {
				Page int `json:"page"`
				Size int `json:"size"`
			} `json:"pages"`
		}
		var sb0, sb1 pagesBlock
		require.NoError(t, json.Unmarshal(searchBodies[0], &sb0))
		require.NoError(t, json.Unmarshal(searchBodies[1], &sb1))

		assert.Equal(t, prospectPageSize, sb0.Pages.Size,
			"page 0 search size must equal prospectPageSize (%d)", prospectPageSize)
		assert.Equal(t, prospectPageSize, sb1.Pages.Size,
			"page 1 search size must equal prospectPageSize (%d) — NOT shrunk to remaining", prospectPageSize)
		assert.Equal(t, sb0.Pages.Size, sb1.Pages.Size,
			"pages.size must be CONSTANT across all pages (regression: size must not shrink on later pages)")

		// Correct page offsets: page 0 → offset 0, page 1 → offset 1.
		assert.Equal(t, 0, sb0.Pages.Page, "first search request must be page 0")
		assert.Equal(t, 1, sb1.Pages.Page, "second search request must be page 1")

		// Credits: page0 search(1) + page0 enrich(50) + page1 search(1) + page1 enrich(25) = 77
		assert.Equal(t, 77, result.CreditsCharged,
			"credits must accumulate across both search and enrich calls")
	})

	t.Run("collect_all fetches both pages and accumulates contacts and credits", func(t *testing.T) {
		srv := newSmallPaginationServer(t)
		defer srv.Close()
		c := newTestClient(srv.URL)
		result, err := c.SearchDomain(context.Background(), "example.com", 0)
		require.NoError(t, err)
		assert.Equal(t, 3, result.Total)
		require.Len(t, result.Contacts, 3, "must collect all 3 contacts across 2 pages")
		// Credits: page0 search(1) + page0 enrich(2) + page1 search(1) + page1 enrich(1) = 5
		assert.Equal(t, 5, result.CreditsCharged, "credits must be summed across all search and enrich calls")
	})

	t.Run("limit=5 single page", func(t *testing.T) {
		srv := newSmallPaginationServer(t)
		defer srv.Close()
		c := newTestClient(srv.URL)
		result, err := c.SearchDomain(context.Background(), "example.com", 5)
		require.NoError(t, err)
		// Only 3 total contacts exist; limit=5 collects all without truncation.
		assert.LessOrEqual(t, len(result.Contacts), 5,
			"limit=5 must produce at most 5 contacts")
		assert.Equal(t, 3, result.Total)
	})
}

func TestSearchDomain_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow server: sleeps longer than the ctx deadline.
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.SearchDomain(ctx, "example.com", 0)
	require.Error(t, err, "context cancellation must produce an error")
}

// TestToProspectContact verifies the prospecting-specific field mapping
// (emailAddresses, phoneNumbers, seniority[].value differ from single-identity).
func TestToProspectContact(t *testing.T) {
	d := &prospectEnrichData{
		FirstName:   "Bruna",
		LastName:    "White",
		FullName:    "Bruna White",
		JobTitle:    "Assistant Director",
		CompanyName: "Fox",
	}
	d.Location.Country = "United States"
	d.EmailAddresses = []struct {
		Email           string `json:"email"`
		EmailType       string `json:"emailType"`
		EmailConfidence string `json:"emailConfidence"`
	}{
		{Email: "bruna.white@fox.com", EmailType: "work", EmailConfidence: "A+"},
	}
	d.PhoneNumbers = []struct {
		Number    string `json:"number"`
		PhoneType string `json:"phoneType"`
		DoNotCall bool   `json:"doNotCall"`
	}{
		{Number: "+1 818", PhoneType: "phone", DoNotCall: true},
	}
	d.SocialLinks.Linkedin = "https://linkedin.com/in/bw"
	d.Departments = []string{"Other"}
	d.Seniority = []struct {
		ID    int    `json:"id"`
		Value string `json:"value"`
	}{
		{ID: 6, Value: "director"},
	}

	got := toProspectContact(d)
	assert.Equal(t, "Bruna White", got.Name)
	assert.Equal(t, "Bruna", got.FirstName)
	assert.Equal(t, "White", got.LastName)
	assert.Equal(t, "Assistant Director", got.JobTitle)
	assert.Equal(t, "Fox", got.Company)
	assert.Equal(t, "United States", got.Location)
	assert.Equal(t, "https://linkedin.com/in/bw", got.LinkedIn)
	assert.Equal(t, []string{"Other"}, got.Departments)
	assert.Equal(t, "director", got.Seniority)

	require.Len(t, got.Emails, 1)
	assert.Equal(t, "bruna.white@fox.com", got.Emails[0].Address)
	assert.Equal(t, "work", got.Emails[0].Type)
	assert.Equal(t, "A+", got.Emails[0].Confidence)

	require.Len(t, got.Phones, 1)
	assert.True(t, got.Phones[0].DoNotCall, "DoNotCall must be preserved (P0-DNC)")
	assert.Equal(t, "+1 818", got.Phones[0].Number)
}
