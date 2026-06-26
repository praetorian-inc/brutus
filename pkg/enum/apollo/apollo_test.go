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

package apollo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

// newTestClient creates a Client pointed at baseURL, overriding the default
// base URL set by NewClient. Mirrors hunter_test.go:122-126.
func newTestClient(baseURL string) *Client {
	c := NewClient("testkey", 5*time.Second, 10)
	c.baseURL = baseURL
	return c
}

// ---------------------------------------------------------------------------
// T001: toPerson + APIError
// ---------------------------------------------------------------------------

func TestToPerson(t *testing.T) {
	src := &apolloPerson{
		ID:           "abc123",
		FirstName:    "Alice",
		LastName:     "Smith",
		Name:         "Alice Smith",
		Title:        "VP Engineering",
		Seniority:    "director",
		Departments:  []string{"Engineering", "Product"},
		Organization: apolloOrganization{Name: "Example Corp"},
	}
	got := toPerson(src)

	assert.Equal(t, "abc123", got.ID)
	assert.Equal(t, "Alice", got.FirstName)
	assert.Equal(t, "Smith", got.LastName)
	assert.Equal(t, "Alice Smith", got.Name)
	assert.Equal(t, "VP Engineering", got.Title)
	assert.Equal(t, "director", got.Seniority)
	assert.Equal(t, "Engineering", got.Department, "first department should be used")
	assert.Equal(t, "Example Corp", got.Organization)

	// PII fields must remain empty — search result is free, no email.
	assert.Empty(t, got.Email, "Email must be empty in search result")
	assert.Empty(t, got.EmailStatus, "EmailStatus must be empty in search result")
	assert.False(t, got.Revealed, "Revealed must be false in search result")
}

func TestToPerson_EmptyDepartments(t *testing.T) {
	src := &apolloPerson{
		ID:   "empty-dept",
		Name: "Bob",
	}
	got := toPerson(src)
	assert.Empty(t, got.Department, "empty departments slice should yield empty Department")
}

func TestAPIError_Unwrap(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		sentinel   error
		wantIs     bool
	}{
		{"401 maps to ErrUnauthorized", http.StatusUnauthorized, ErrUnauthorized, true},
		{"403 maps to ErrForbidden", http.StatusForbidden, ErrForbidden, true},
		{"422 maps to ErrBadRequest", http.StatusUnprocessableEntity, ErrBadRequest, true},
		{"429 maps to ErrRateLimited", http.StatusTooManyRequests, ErrRateLimited, true},
		{"500 does not map to ErrUnauthorized", http.StatusInternalServerError, ErrUnauthorized, false},
		{"500 does not map to ErrForbidden", http.StatusInternalServerError, ErrForbidden, false},
		{"500 does not map to ErrBadRequest", http.StatusInternalServerError, ErrBadRequest, false},
		{"500 does not map to ErrRateLimited", http.StatusInternalServerError, ErrRateLimited, false},
		{"500 Unwrap returns nil", http.StatusInternalServerError, nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &APIError{StatusCode: tc.statusCode, Details: "test"}
			if tc.sentinel == nil {
				// Special case: assert Unwrap() is nil.
				assert.Nil(t, err.Unwrap())
				return
			}
			assert.Equal(t, tc.wantIs, errors.Is(err, tc.sentinel))
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	// Error() must include the HTTP status code.
	err := &APIError{StatusCode: 401, Details: "SECRETKEY-DO-NOT-LEAK"}
	msg := err.Error()
	assert.Contains(t, msg, "401")
	// P0-1 security fix: Details must NOT appear in Error() output.
	assert.NotContains(t, msg, "SECRETKEY-DO-NOT-LEAK",
		"APIError.Error() must not include Details (P0-1 key-leak prevention)")
}

// ---------------------------------------------------------------------------
// T002: searchPage + matchPerson + do
// ---------------------------------------------------------------------------

func makeSearchResponse(people []apolloPerson, total, page, perPage int) []byte {
	resp := apolloSearchResponse{
		People: people,
		Pagination: apolloPagination{
			Page:         page,
			PerPage:      perPage,
			TotalEntries: total,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func makeMatchResponse(email, emailStatus string) []byte {
	resp := apolloMatchResponse{
		Person: apolloPerson{
			Email:       email,
			EmailStatus: emailStatus,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestSearchPage_Decode(t *testing.T) {
	people := []apolloPerson{
		{
			ID:           "p1",
			FirstName:    "Alice",
			LastName:     "Smith",
			Name:         "Alice Smith",
			Title:        "Engineer",
			Seniority:    "senior",
			Departments:  []string{"Engineering"},
			Organization: apolloOrganization{Name: "ACME Corp"},
		},
		{
			ID:           "p2",
			FirstName:    "Bob",
			LastName:     "Jones",
			Name:         "Bob Jones",
			Title:        "Manager",
			Organization: apolloOrganization{Name: "ACME Corp"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeSearchResponse(people, 2, 1, 10))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	got, total, err := c.searchPage(context.Background(), "example.com", nil, 1)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, got, 2)

	assert.Equal(t, "p1", got[0].ID)
	assert.Equal(t, "Alice Smith", got[0].Name)
	assert.Equal(t, "Engineer", got[0].Title)
	assert.Equal(t, "ACME Corp", got[0].Organization)
	assert.Empty(t, got[0].Email, "Email must be empty in search result")
	assert.False(t, got[0].Revealed, "Revealed must be false in search result")

	assert.Equal(t, "p2", got[1].ID)
}

func TestSearchPage_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, _, err := c.searchPage(context.Background(), "example.com", nil, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized), "expected ErrUnauthorized, got %v", err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, 401, apiErr.StatusCode)
}

func TestSearchPage_422(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"invalid params"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, _, err := c.searchPage(context.Background(), "example.com", nil, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBadRequest), "expected ErrBadRequest, got %v", err)
}

func TestMatchPerson_Decode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponse("alice@example.com", "verified"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	email, status, err := c.matchPerson(context.Background(), "p1")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", email)
	assert.Equal(t, "verified", status)
}

func TestDo_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	// searchPage uses do() internally; a 200 with bad JSON triggers a decode error.
	_, _, err := c.searchPage(context.Background(), "example.com", nil, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding apollo search response")
}

func TestDo_SetsAuthHeader(t *testing.T) {
	var capturedHeader string
	var capturedURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get(headerAPIKey)
		capturedURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeSearchResponse(nil, 0, 1, 10))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, _, err := c.searchPage(context.Background(), "example.com", nil, 1)
	require.NoError(t, err)

	// X-Api-Key must be set as a header with the correct value.
	assert.Equal(t, "testkey", capturedHeader, "X-Api-Key header must be set")

	// The key must NOT appear in the request URL (P0-1: header-based auth only).
	assert.NotContains(t, capturedURL, "testkey", "API key must not appear in URL")
}

// ---------------------------------------------------------------------------
// T003: SearchPeople pagination + RevealEmails
// ---------------------------------------------------------------------------

// pagedSearchServer returns an httptest.Server that serves paginated Apollo
// search results (page-based, not offset-based). Each request must include a
// `page` field in the JSON body. midErrPage triggers a 429 when page >= midErrPage.
func pagedSearchServer(t *testing.T, allPeople []apolloPerson, total, pageSize, midErrPage int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req apolloSearchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		page := req.Page
		if page <= 0 {
			page = 1
		}

		if midErrPage > 0 && page >= midErrPage {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}

		start := (page - 1) * pageSize
		end := start + pageSize
		if start > len(allPeople) {
			start = len(allPeople)
		}
		if end > len(allPeople) {
			end = len(allPeople)
		}
		pageSlice := allPeople[start:end]

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeSearchResponse(pageSlice, total, page, pageSize))
	}))

	return srv, &requestCount
}

func makePerson(id string) apolloPerson {
	return apolloPerson{
		ID:           id,
		Name:         "Person " + id,
		Title:        "Engineer",
		Organization: apolloOrganization{Name: "Corp"},
	}
}

func TestSearchPeople_Pagination(t *testing.T) {
	tests := []struct {
		name         string
		allPeople    []apolloPerson
		total        int
		pageSize     int
		limit        int
		midErrPage   int
		wantPeople   int
		wantRequests int32
		wantErr      error
	}{
		{
			name:         "single page — all fit",
			allPeople:    []apolloPerson{makePerson("p1"), makePerson("p2"), makePerson("p3")},
			total:        3,
			pageSize:     10,
			limit:        0,
			wantPeople:   3,
			wantRequests: 1,
		},
		{
			name: "two full pages plus short final",
			allPeople: []apolloPerson{
				makePerson("p1"), makePerson("p2"),
				makePerson("p3"), makePerson("p4"),
				makePerson("p5"),
			},
			total:        5,
			pageSize:     2,
			limit:        0,
			wantPeople:   5,
			wantRequests: 3,
		},
		{
			name:         "empty domain — 0 people, 1 request",
			allPeople:    []apolloPerson{},
			total:        0,
			pageSize:     10,
			limit:        0,
			wantPeople:   0,
			wantRequests: 1,
		},
		{
			name: "--limit=2 of 5 available returns exactly 2",
			allPeople: []apolloPerson{
				makePerson("p1"), makePerson("p2"),
				makePerson("p3"), makePerson("p4"),
				makePerson("p5"),
			},
			total:        5,
			pageSize:     10,
			limit:        2,
			wantPeople:   2,
			wantRequests: 1,
		},
		{
			name: "mid-pagination 429 → ErrRateLimited, partial result non-nil",
			allPeople: []apolloPerson{
				makePerson("p1"), makePerson("p2"),
				makePerson("p3"),
			},
			total:      3,
			pageSize:   2,
			limit:      0,
			midErrPage: 2,
			wantPeople: 2, // first page of 2 fetched before error
			wantErr:    ErrRateLimited,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, reqCount := pagedSearchServer(t, tc.allPeople, tc.total, tc.pageSize, tc.midErrPage)
			defer srv.Close()

			c := newTestClient(srv.URL)
			c.pageSize = tc.pageSize

			result, err := c.SearchPeople(context.Background(), "example.com", nil, tc.limit)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "expected %v, got %v", tc.wantErr, err)
				// SearchPeople returns a non-nil partial result even on mid-pagination error.
				require.NotNil(t, result, "partial result must be non-nil on mid-pagination error")
				assert.Equal(t, tc.wantPeople, len(result.People),
					"partial result must contain pages fetched before error")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantPeople, len(result.People))
			assert.Equal(t, tc.wantRequests, reqCount.Load())
		})
	}
}

func TestSearchPeople_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server that outlasts the context timeout.
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeSearchResponse([]apolloPerson{makePerson("p1")}, 100, 1, 1))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.pageSize = 1

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.SearchPeople(ctx, "example.com", nil, 0)
	require.Error(t, err, "expected error due to context cancellation")
}

// ---------------------------------------------------------------------------
// RevealEmails tests
// ---------------------------------------------------------------------------

func TestRevealEmails_Merge(t *testing.T) {
	// 3 people: server returns email for p1, email for p2, empty for p3.
	// All 3 should get Revealed=true (partial-result honesty); result.Revealed=true.
	responses := map[string]string{
		"p1": "alice@example.com",
		"p2": "bob@example.com",
		"p3": "", // no email returned
	}
	statuses := map[string]string{
		"p1": "verified",
		"p2": "verified",
		"p3": "unknown",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apolloMatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		email := responses[req.ID]
		status := statuses[req.ID]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponse(email, status))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result := &DomainResult{
		Domain: "example.com",
		People: []Person{
			{ID: "p1"},
			{ID: "p2"},
			{ID: "p3"},
		},
	}

	err := c.RevealEmails(context.Background(), result)
	require.NoError(t, err)

	assert.Equal(t, "alice@example.com", result.People[0].Email)
	assert.True(t, result.People[0].Revealed)

	assert.Equal(t, "bob@example.com", result.People[1].Email)
	assert.True(t, result.People[1].Revealed)

	// Third person: empty email but still Revealed=true (partial-result honesty).
	assert.Empty(t, result.People[2].Email)
	assert.True(t, result.People[2].Revealed, "Revealed=true even when email is empty")

	// result.Revealed is set when there were people to reveal.
	assert.True(t, result.Revealed)
}

func TestRevealEmails_SkipsEmptyID(t *testing.T) {
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponse("alice@example.com", "verified"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result := &DomainResult{
		Domain: "example.com",
		People: []Person{
			{ID: ""},   // must be skipped — no match call
			{ID: "p2"}, // should be revealed
			{ID: ""},   // must be skipped
		},
	}

	err := c.RevealEmails(context.Background(), result)
	require.NoError(t, err)

	// Only the person with a non-empty ID should have triggered a request.
	assert.Equal(t, int32(1), requestCount.Load(), "only 1 match request for the non-empty ID")
	assert.False(t, result.People[0].Revealed, "empty-ID person should not be revealed")
	assert.True(t, result.People[1].Revealed)
	assert.False(t, result.People[2].Revealed, "empty-ID person should not be revealed")
}

func TestRevealEmails_SerialCount(t *testing.T) {
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponse(fmt.Sprintf("user%d@example.com", requestCount.Load()), "verified"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result := &DomainResult{
		Domain: "example.com",
		People: []Person{
			{ID: "p1"}, {ID: "p2"}, {ID: "p3"}, {ID: "p4"}, {ID: "p5"},
		},
	}

	err := c.RevealEmails(context.Background(), result)
	require.NoError(t, err)
	assert.Equal(t, int32(5), requestCount.Load(), "exactly 5 match requests for 5 people")
}

// TestRevealEmails_ResultRevealedOnFirstSuccess asserts that result.Revealed is
// set to true after the FIRST successful match, even if a later match fails.
// This reflects that credits were spent for the successful reveals.
func TestRevealEmails_ResultRevealedOnFirstSuccess(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			// First match succeeds.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeMatchResponse("alice@example.com", "verified"))
			return
		}
		// Second match returns a 429 — simulates a failure after the first success.
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result := &DomainResult{
		Domain: "example.com",
		People: []Person{
			{ID: "p1"},
			{ID: "p2"},
		},
	}

	err := c.RevealEmails(context.Background(), result)
	// The second match fails — RevealEmails surfaces the error.
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited))

	// result.Revealed must be true because the FIRST match succeeded (credits spent).
	assert.True(t, result.Revealed,
		"result.Revealed must be true once any match succeeds, even if later matches fail")
	// First person has their email and Revealed=true.
	assert.Equal(t, "alice@example.com", result.People[0].Email)
	assert.True(t, result.People[0].Revealed)
}
