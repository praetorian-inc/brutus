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
	c, _ := NewClient("testkey", 5*time.Second, 10, "") // Empty proxy never errors.
	c.baseURL = baseURL
	return c
}

// ---------------------------------------------------------------------------
// T001: toPerson + APIError
// ---------------------------------------------------------------------------

func TestToPerson(t *testing.T) {
	src := apolloPerson{
		ID:           "abc123",
		FirstName:    "Alice",
		LastName:     "Smith",
		Name:         "Alice Smith",
		Title:        "VP Engineering",
		Seniority:    "director",
		Departments:  []string{"Engineering", "Product"},
		Organization: apolloOrganization{Name: "Example Corp"},
	}
	got := src.toPerson()

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
	src := apolloPerson{
		ID:   "empty-dept",
		Name: "Bob",
	}
	got := src.toPerson()
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

func makeSearchResponse(people []apolloPerson, total int) []byte {
	resp := apolloSearchResponse{
		People:       people,
		TotalEntries: total,
	}
	b, _ := json.Marshal(resp)
	return b
}

// makeMatchResponse returns a full apolloMatchResponse JSON payload with the
// reveal-only fields populated. The extra fields (linkedin_url, last_name,
// seniority, departments, city/state/country, employment_history) mirror what
// people/match returns and must be preserved through mergeReveal.
func makeMatchResponse(email, emailStatus string) []byte {
	resp := apolloMatchResponse{
		Person: apolloPerson{
			FirstName:   "Alice",
			LastName:    "Smith",
			Name:        "Alice Smith",
			Email:       email,
			EmailStatus: emailStatus,
			LinkedinURL: "https://linkedin.com/in/alice",
			TwitterURL:  "https://twitter.com/alice",
			Seniority:   "senior",
			Departments: []string{"Engineering"},
			City:        "San Francisco",
			State:       "CA",
			Country:     "United States",
			EmploymentHistory: []apolloEmploymentEntry{
				{OrganizationName: "Example Corp", Title: "Engineer", StartDate: "2020-01", Current: true},
			},
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
		_, _ = w.Write(makeSearchResponse(people, 2))
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
	person, err := c.matchPerson(context.Background(), "p1")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", person.Email)
	assert.Equal(t, "verified", person.EmailStatus)
	assert.Equal(t, "https://linkedin.com/in/alice", person.LinkedinURL)
	assert.Equal(t, "Smith", person.LastName)
	assert.Equal(t, "senior", person.Seniority)
	assert.Equal(t, []string{"Engineering"}, person.Departments)
	assert.Equal(t, "San Francisco", person.City)
	assert.Equal(t, "CA", person.State)
	assert.Equal(t, "United States", person.Country)
	require.Len(t, person.Employment, 1)
	assert.Equal(t, "Example Corp", person.Employment[0].Organization)
	assert.True(t, person.Employment[0].Current)
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
		_, _ = w.Write(makeSearchResponse(nil, 0))
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
// T003: Discover pagination (was SearchPeople) + EnrichByIDs + RevealEmails
// ---------------------------------------------------------------------------

// pagedSearchServer returns an httptest.Server that serves paginated Apollo
// search results (page-based, not offset-based). Each request must include a
// `page` field in the JSON body. midErrPage triggers a 429 when page >= midErrPage.
// matchFail, when true, causes the server to fail the test immediately if the
// /people/match path is called — used to assert Discover never spends credits.
func pagedSearchServer(t *testing.T, allPeople []apolloPerson, total, pageSize, midErrPage int, matchFail bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Discover must NEVER call /people/match — that spends credits.
		if matchFail && r.URL.Path == matchPath {
			t.Errorf("Discover must not call /people/match (credits would be charged), but got request to %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

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
		_, _ = w.Write(makeSearchResponse(pageSlice, total))
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

// makePersonWithAvailability creates an apolloPerson with known availability flags.
// hasDirectPhone follows the live Apollo API: "Yes" means available, any other
// string (e.g. "Maybe: ...") means not available.
func makePersonWithAvailability(id string, hasEmail bool, hasDirectPhone string) apolloPerson {
	return apolloPerson{
		ID:             id,
		Name:           "Person " + id,
		Title:          "Engineer",
		Organization:   apolloOrganization{Name: "Corp"},
		HasEmail:       hasEmail,
		HasDirectPhone: hasDirectPhone,
	}
}

func TestDiscover_Pagination(t *testing.T) {
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
			// matchFail=true: Discover must never call /people/match.
			srv, reqCount := pagedSearchServer(t, tc.allPeople, tc.total, tc.pageSize, tc.midErrPage, true)
			defer srv.Close()

			c := newTestClient(srv.URL)
			c.pageSize = tc.pageSize

			result, err := c.Discover(context.Background(), "example.com", nil, tc.limit)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "expected %v, got %v", tc.wantErr, err)
				// Discover returns a non-nil partial result even on mid-pagination error.
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

// TestDiscover_NoMatchCalls asserts that Discover (the free tier) never calls
// /people/match regardless of the number of people returned. Calling match would
// silently spend Apollo credits.
func TestDiscover_NoMatchCalls(t *testing.T) {
	people := []apolloPerson{
		makePersonWithAvailability("p1", true, "Yes"),
		makePersonWithAvailability("p2", false, "Maybe: could be work email"),
		makePersonWithAvailability("p3", true, ""),
	}
	// matchFail=true: any call to /people/match causes the test to fail.
	srv, _ := pagedSearchServer(t, people, 3, 10, 0, true)
	defer srv.Close()

	c := newTestClient(srv.URL)
	result, err := c.Discover(context.Background(), "example.com", nil, 0)
	require.NoError(t, err)
	require.Len(t, result.People, 3)

	// Discovery sets no emails — the free search tier never reveals PII.
	for i, p := range result.People {
		assert.Empty(t, p.Email, "person[%d] Email must be empty from Discover (free tier)", i)
		assert.False(t, p.Revealed, "person[%d] Revealed must be false after Discover", i)
	}
	// result.Revealed is never set by Discover — credits were NOT spent.
	assert.False(t, result.Revealed, "DomainResult.Revealed must be false after Discover-only")
	assert.Zero(t, result.CreditsCharged, "CreditsCharged must be 0 after Discover-only")
}

// TestDiscover_HasEmailHasPhoneMapping verifies that HasEmail and HasPhone are
// mapped correctly from the search-tier JSON. The key case: has_direct_phone is
// a STRING in Apollo's API — "Yes" maps to HasPhone=true, anything else
// (including "Maybe: ...", empty string, or any vendor-defined variation) maps
// to HasPhone=false.
func TestDiscover_HasEmailHasPhoneMapping(t *testing.T) {
	people := []apolloPerson{
		// has_email:true, has_direct_phone:"Yes" → both true
		makePersonWithAvailability("p1", true, "Yes"),
		// has_email:false, has_direct_phone:"Maybe: could be work" → phone false
		makePersonWithAvailability("p2", false, "Maybe: could be work email"),
		// has_email:true, has_direct_phone:"" → phone false (empty string)
		makePersonWithAvailability("p3", true, ""),
		// has_email:false, has_direct_phone:"No" → both false
		makePersonWithAvailability("p4", false, "No"),
	}
	srv, _ := pagedSearchServer(t, people, 4, 10, 0, true)
	defer srv.Close()

	c := newTestClient(srv.URL)
	result, err := c.Discover(context.Background(), "example.com", nil, 0)
	require.NoError(t, err)
	require.Len(t, result.People, 4)

	// p1: has_email=true, has_direct_phone="Yes" → both flags true
	assert.True(t, result.People[0].HasEmail, "p1: has_email:true must map to HasEmail=true")
	assert.True(t, result.People[0].HasPhone, `p1: has_direct_phone:"Yes" must map to HasPhone=true`)

	// p2: has_email=false, has_direct_phone="Maybe: ..." → phone false (non-"Yes" string)
	assert.False(t, result.People[1].HasEmail, "p2: has_email:false must map to HasEmail=false")
	assert.False(t, result.People[1].HasPhone, `p2: has_direct_phone:"Maybe:..." must map to HasPhone=false (non-"Yes" string)`)

	// p3: has_email=true, has_direct_phone="" → phone false (empty string != "Yes")
	assert.True(t, result.People[2].HasEmail, "p3: has_email:true must map to HasEmail=true")
	assert.False(t, result.People[2].HasPhone, `p3: has_direct_phone:"" must map to HasPhone=false`)

	// p4: has_email=false, has_direct_phone="No" → both false
	assert.False(t, result.People[3].HasEmail, "p4: has_email:false must map to HasEmail=false")
	assert.False(t, result.People[3].HasPhone, `p4: has_direct_phone:"No" must map to HasPhone=false`)
}

func TestDiscover_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server that outlasts the context timeout.
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeSearchResponse([]apolloPerson{makePerson("p1")}, 100))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.pageSize = 1

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Discover(ctx, "example.com", nil, 0)
	require.Error(t, err, "expected error due to context cancellation")
}

// ---------------------------------------------------------------------------
// T003b: EnrichByIDs — selective per-id enrichment
// ---------------------------------------------------------------------------

// makeMatchResponseForID returns a full apolloMatchResponse JSON payload for the
// given Apollo person id. The email is derived from the id so each person gets a
// distinct email, making assertions straightforward.
func makeMatchResponseForID(id string) []byte {
	resp := apolloMatchResponse{
		Person: apolloPerson{
			ID:          id,
			FirstName:   "Person",
			LastName:    id,
			Name:        "Person " + id,
			Email:       id + "@example.com",
			EmailStatus: "verified",
			LinkedinURL: "https://linkedin.com/in/" + id,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestEnrichByIDs_ReturnsEnrichedPersons(t *testing.T) {
	var matchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, matchPath, r.URL.Path, "EnrichByIDs must call /people/match")
		matchCount.Add(1)
		var req apolloMatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponseForID(req.ID))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	ids := []string{"p1", "p2", "p3"}

	enriched, err := c.EnrichByIDs(context.Background(), ids)
	require.NoError(t, err)
	require.Len(t, enriched, 3, "EnrichByIDs must return one Person per id")

	// One /people/match call per id.
	assert.Equal(t, int32(3), matchCount.Load(), "must call /people/match once per id")

	// Each enriched person has the correct id, email (set from id), and Revealed=true.
	for i, id := range ids {
		assert.Equal(t, id, enriched[i].ID, "person[%d] ID must match requested id", i)
		assert.Equal(t, id+"@example.com", enriched[i].Email, "person[%d] Email must be populated", i)
		assert.Equal(t, "verified", enriched[i].EmailStatus)
		assert.Equal(t, "https://linkedin.com/in/"+id, enriched[i].LinkedinURL)
		assert.True(t, enriched[i].Revealed, "person[%d] Revealed must be true after EnrichByIDs", i)
	}
}

func TestEnrichByIDs_SkipsEmptyIDs(t *testing.T) {
	var matchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		matchCount.Add(1)
		var req apolloMatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeMatchResponseForID(req.ID))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	ids := []string{"", "p2", ""}

	enriched, err := c.EnrichByIDs(context.Background(), ids)
	require.NoError(t, err)
	require.Len(t, enriched, 1, "empty ids must be skipped")
	assert.Equal(t, int32(1), matchCount.Load(), "only one match call for the non-empty id")
	assert.Equal(t, "p2", enriched[0].ID)
}

func TestEnrichByIDs_SurfacesFirstError(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			var req apolloMatchRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeMatchResponseForID(req.ID))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	enriched, err := c.EnrichByIDs(context.Background(), []string{"p1", "p2", "p3"})

	// Error from the second call is surfaced.
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited))

	// Records enriched before the error are still returned (credits already spent).
	require.Len(t, enriched, 1, "must return records enriched before the error")
	assert.Equal(t, "p1", enriched[0].ID)
	assert.True(t, enriched[0].Revealed)
}

// ---------------------------------------------------------------------------
// RevealEmails tests
// ---------------------------------------------------------------------------

func TestRevealEmails_Merge(t *testing.T) {
	// 3 people: server returns email for p1, email for p2, empty for p3.
	// All 3 should get Revealed=true (partial-result honesty); result.Revealed=true.
	// makeMatchResponse now includes full reveal fields (linkedin_url, last_name,
	// seniority, departments, city/state/country, employment_history).
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

	// p1: full reveal fields merged.
	assert.Equal(t, "alice@example.com", result.People[0].Email)
	assert.Equal(t, "verified", result.People[0].EmailStatus)
	assert.Equal(t, "https://linkedin.com/in/alice", result.People[0].LinkedinURL)
	assert.Equal(t, "Smith", result.People[0].LastName)
	assert.Equal(t, "senior", result.People[0].Seniority)
	assert.Equal(t, []string{"Engineering"}, result.People[0].Departments)
	assert.Equal(t, "San Francisco", result.People[0].City)
	assert.Equal(t, "United States", result.People[0].Country)
	require.Len(t, result.People[0].Employment, 1)
	assert.True(t, result.People[0].Employment[0].Current)
	assert.True(t, result.People[0].Revealed)

	// p2: also merged.
	assert.Equal(t, "bob@example.com", result.People[1].Email)
	assert.True(t, result.People[1].Revealed)

	// Third person: empty email but still Revealed=true (partial-result honesty).
	assert.Empty(t, result.People[2].Email)
	assert.True(t, result.People[2].Revealed, "Revealed=true even when email is empty")

	// result.Revealed is set when there were people to reveal.
	assert.True(t, result.Revealed)
	// CreditsCharged == number of people enriched (all 3, including the one with no email).
	assert.Equal(t, 3, result.CreditsCharged, "CreditsCharged must equal number of people enriched")
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

// TestRevealEmails_DeduplicatesIDs asserts that a duplicate person id (which
// pagination can surface) triggers only ONE /people/match call — enriching the
// same id twice would burn a credit for an already-revealed record.
func TestRevealEmails_DeduplicatesIDs(t *testing.T) {
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
			{ID: "p1"},
			{ID: "p1"}, // duplicate — must NOT trigger a second match call
			{ID: "p2"},
		},
	}

	err := c.RevealEmails(context.Background(), result)
	require.NoError(t, err)

	// Two unique ids -> exactly two match calls (not three).
	assert.Equal(t, int32(2), requestCount.Load(), "duplicate id must not trigger a second match call")
	// CreditsCharged counts unique enriched ids, not raw rows.
	assert.Equal(t, 2, result.CreditsCharged, "CreditsCharged must count unique ids only")
	// Both duplicate rows still get the merged email.
	assert.Equal(t, "alice@example.com", result.People[0].Email)
	assert.Equal(t, "alice@example.com", result.People[1].Email)
	assert.Equal(t, "alice@example.com", result.People[2].Email)
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
	// CreditsCharged reflects the number of enriched people — one per match call.
	assert.Equal(t, 5, result.CreditsCharged, "CreditsCharged must equal 5 (one per person)")
	assert.True(t, result.Revealed, "result.Revealed must be true after successful enrichment")
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
