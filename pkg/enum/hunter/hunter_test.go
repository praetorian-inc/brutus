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

package hunter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Task 1: toPerson + APIError/Unwrap
// ---------------------------------------------------------------------------

func TestToPerson(t *testing.T) {
	src := apiEmail{
		Value:      "alice@example.com",
		Type:       "personal",
		Confidence: 90,
		FirstName:  "Alice",
		LastName:   "Smith",
		Position:   "Engineer",
		Seniority:  "senior",
		Department: "Engineering",
		Phone:      "+1-555-0100",
		LinkedIn:   "https://linkedin.com/in/alice",
		Twitter:    "https://twitter.com/alice",
		Sources: []apiSource{
			{URI: "https://example.com/alice"},
			{URI: "https://linkedin.com/in/alice"},
		},
	}
	got := toPerson(&src)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, "personal", got.Type)
	assert.Equal(t, 90, got.Confidence)
	assert.Equal(t, "Alice", got.FirstName)
	assert.Equal(t, "Smith", got.LastName)
	assert.Equal(t, "Engineer", got.Position)
	assert.Equal(t, "senior", got.Seniority)
	assert.Equal(t, "Engineering", got.Department)
	assert.Equal(t, "+1-555-0100", got.Phone)
	assert.Equal(t, "https://linkedin.com/in/alice", got.LinkedIn)
	assert.Equal(t, "https://twitter.com/alice", got.Twitter)
	assert.Equal(t, []string{"https://example.com/alice", "https://linkedin.com/in/alice"}, got.Sources)
}

func TestAPIError_Unwrap(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		sentinel   error
		wantIs     bool
	}{
		{"401 maps to ErrUnauthorized", http.StatusUnauthorized, ErrUnauthorized, true},
		{"429 maps to ErrRateLimited", http.StatusTooManyRequests, ErrRateLimited, true},
		{"451 maps to ErrLegalReasons", http.StatusUnavailableForLegalReasons, ErrLegalReasons, true},
		{"500 does not map to ErrUnauthorized", http.StatusInternalServerError, ErrUnauthorized, false},
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
	err := &APIError{StatusCode: 401, Details: "No valid API key"}
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "No valid API key")
}

// ---------------------------------------------------------------------------
// Task 2: fetchPage - single-page success + error mapping
// ---------------------------------------------------------------------------

func makeResponse(domain, org string, emails []apiEmail, total, limit, offset int) []byte {
	resp := apiResponse{
		Data: apiData{
			Domain:       domain,
			Organization: org,
			Emails:       emails,
		},
		Meta: apiMeta{
			Results: total,
			Limit:   limit,
			Offset:  offset,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func makeErrorResponse(details string) []byte {
	resp := apiResponse{
		Errors: []apiError{{ID: "err", Code: 1, Details: details}},
	}
	b, _ := json.Marshal(resp)
	return b
}

func newTestClient(baseURL string) *Client {
	c := NewClient("testkey", 5*time.Second, 10)
	c.baseURL = baseURL
	return c
}

func TestFetchPage_200Decode(t *testing.T) {
	emails := []apiEmail{
		{Value: "a@example.com", Confidence: 80, FirstName: "A", Sources: []apiSource{{URI: "https://src1.com"}}},
		{Value: "b@example.com", Confidence: 70},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "testkey", q.Get("api_key"))
		assert.Equal(t, "example.com", q.Get("domain"))
		assert.Equal(t, "10", q.Get("limit"))
		assert.Equal(t, "0", q.Get("offset"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeResponse("example.com", "Example Corp", emails, 2, 10, 0))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	page, err := c.fetchPage(context.Background(), "example.com", 0)
	require.NoError(t, err)
	assert.Equal(t, "Example Corp", page.Data.Organization)
	assert.Len(t, page.Data.Emails, 2)
	assert.Equal(t, "a@example.com", page.Data.Emails[0].Value)
	assert.Equal(t, 80, page.Data.Emails[0].Confidence)
	assert.Equal(t, "https://src1.com", page.Data.Emails[0].Sources[0].URI)
}

func TestFetchPage_401_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(makeErrorResponse("No valid API key"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.fetchPage(context.Background(), "example.com", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized), "expected ErrUnauthorized, got %v", err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, 401, apiErr.StatusCode)
	assert.Contains(t, apiErr.Details, "No valid API key")
}

func TestFetchPage_429_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write(makeErrorResponse("rate limit exceeded"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.fetchPage(context.Background(), "example.com", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited))
}

func TestFetchPage_451_LegalReasons(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
		_, _ = w.Write(makeErrorResponse("unavailable for legal reasons"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.fetchPage(context.Background(), "example.com", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLegalReasons))
}

func TestFetchPage_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.fetchPage(context.Background(), "example.com", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding hunter response")
}

func TestFetchPage_QueryParams(t *testing.T) {
	var capturedURL *url.URL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeResponse("test.io", "Test", nil, 0, 10, 0))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, err := c.fetchPage(context.Background(), "test.io", 5)
	require.NoError(t, err)

	q := capturedURL.Query()
	assert.Equal(t, "test.io", q.Get("domain"))
	assert.Equal(t, "testkey", q.Get("api_key"))
	assert.Equal(t, "10", q.Get("limit"))
	assert.Equal(t, "5", q.Get("offset"))
}

// ---------------------------------------------------------------------------
// Task 3: Search pagination loop
// ---------------------------------------------------------------------------

func pagedServer(t *testing.T, allEmails []apiEmail, total, pageSize, midErrOffset int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		q := r.URL.Query()
		offset := 0
		_, _ = fmt.Sscanf(q.Get("offset"), "%d", &offset)

		if midErrOffset > 0 && offset >= midErrOffset {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(makeErrorResponse("rate limit"))
			return
		}

		end := offset + pageSize
		if end > len(allEmails) {
			end = len(allEmails)
		}
		page := allEmails[offset:end]

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeResponse("example.com", "Example Corp", page, total, pageSize, offset))
	}))

	return srv, &requestCount
}

func TestSearch_Pagination(t *testing.T) {
	email := func(v string) apiEmail {
		return apiEmail{Value: v, Confidence: 75}
	}

	tests := []struct {
		name         string
		allEmails    []apiEmail
		total        int
		pageSize     int
		midErrOffset int
		wantPeople   int
		wantRequests int32
		wantErr      error
	}{
		{
			name:         "single page 3 emails",
			allEmails:    []apiEmail{email("a@e.com"), email("b@e.com"), email("c@e.com")},
			total:        3,
			pageSize:     100,
			wantPeople:   3,
			wantRequests: 1,
		},
		{
			name: "two full pages plus short final pageSize 2 total 5",
			allEmails: []apiEmail{
				email("a@e.com"), email("b@e.com"),
				email("c@e.com"), email("d@e.com"),
				email("e@e.com"),
			},
			total:        5,
			pageSize:     2,
			wantPeople:   5,
			wantRequests: 3,
		},
		{
			name:         "empty domain zero people one request",
			allEmails:    []apiEmail{},
			total:        0,
			pageSize:     100,
			wantPeople:   0,
			wantRequests: 1,
		},
		{
			name: "mid pagination 429 stops early",
			allEmails: []apiEmail{
				email("a@e.com"), email("b@e.com"),
				email("c@e.com"),
			},
			total:        3,
			pageSize:     2,
			midErrOffset: 2,
			wantErr:      ErrRateLimited,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, reqCount := pagedServer(t, tc.allEmails, tc.total, tc.pageSize, tc.midErrOffset)
			defer srv.Close()

			c := newTestClient(srv.URL)
			c.pageSize = tc.pageSize

			result, err := c.Search(context.Background(), "example.com")

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "expected %v, got %v", tc.wantErr, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantPeople, len(result.People))
			assert.Equal(t, tc.wantRequests, reqCount.Load())
			if tc.total > 0 {
				assert.Equal(t, "Example Corp", result.Organization)
				assert.Equal(t, tc.total, result.Total)
			}
		})
	}
}

func TestSearch_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := 0
		_, _ = fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)
		// Slow server: sleep longer than ctx timeout so cancellation fires mid-request.
		time.Sleep(200 * time.Millisecond)
		emails := []apiEmail{{Value: fmt.Sprintf("user%d@e.com", offset), Confidence: 80}}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeResponse("example.com", "Corp", emails, 100, 1, offset))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.pageSize = 1

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Search(ctx, "example.com")
	require.Error(t, err)
}
