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

package dehashed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helper: same-package client pointing at a test server.
// ---------------------------------------------------------------------------

func newTestClient(baseURL string) *Client {
	c := NewClient("testkey", 5*time.Second, 10)
	c.baseURL = baseURL
	return c
}

// ---------------------------------------------------------------------------
// Task 1: toRecord identity mapping
// ---------------------------------------------------------------------------

func TestToRecord(t *testing.T) {
	src := &apiEntry{
		ID:           "abc123",
		Email:        []string{"alice@example.com"},
		Username:     []string{"alice"},
		Name:         []string{"Alice Smith"},
		IPAddress:    []string{"1.2.3.4"},
		Phone:        []string{"+1-555-0100"},
		Address:      []string{"123 Main St"},
		DOB:          []string{"1990-01-01"},
		Database:     "breach-db",
		ObtainedDate: "2021-01",
	}
	got := toRecord(src)
	assert.Equal(t, "abc123", got.ID)
	assert.Equal(t, []string{"alice@example.com"}, got.Email)
	assert.Equal(t, []string{"alice"}, got.Username)
	assert.Equal(t, []string{"Alice Smith"}, got.Name)
	assert.Equal(t, []string{"1.2.3.4"}, got.IPAddress)
	assert.Equal(t, []string{"+1-555-0100"}, got.Phone)
	assert.Equal(t, []string{"123 Main St"}, got.Address)
	assert.Equal(t, []string{"1990-01-01"}, got.DOB)
	assert.Equal(t, "breach-db", got.Database)
	assert.Equal(t, "2021-01", got.ObtainedDate)
}

// ---------------------------------------------------------------------------
// Task 2: APIError Unwrap sentinel mapping
// ---------------------------------------------------------------------------

func TestAPIError_Unwrap(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		sentinel   error
		wantIs     bool
	}{
		{"401 maps to ErrUnauthorized", http.StatusUnauthorized, ErrUnauthorized, true},
		{"402 maps to ErrPaymentRequired", http.StatusPaymentRequired, ErrPaymentRequired, true},
		{"403 maps to ErrForbidden", http.StatusForbidden, ErrForbidden, true},
		{"429 maps to ErrRateLimited", http.StatusTooManyRequests, ErrRateLimited, true},
		{"500 does not map to ErrUnauthorized", http.StatusInternalServerError, ErrUnauthorized, false},
		{"500 does not map to ErrPaymentRequired", http.StatusInternalServerError, ErrPaymentRequired, false},
		{"500 does not map to ErrForbidden", http.StatusInternalServerError, ErrForbidden, false},
		{"500 does not map to ErrRateLimited", http.StatusInternalServerError, ErrRateLimited, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &APIError{StatusCode: tc.statusCode, Details: "test"}
			assert.Equal(t, tc.wantIs, errors.Is(err, tc.sentinel))
		})
	}
}

// ---------------------------------------------------------------------------
// P0-SCOPE: TestSearch_DropsCredentials
// Verify that even if the API returns password / hashed_password fields, they
// are never present in the Record, human output, or JSONL output.
// ---------------------------------------------------------------------------

// outputDehashedHumanForTest is a local re-implementation that mirrors what
// cmd/brutus/cmd_enum_dehashed_output.go does so the package-level test can
// exercise both output paths without importing main. It uses the same approach
// as the production code: iterate records and emit email, username, name, database.
func outputDehashedHumanForTest(w *bytes.Buffer, result *DomainResult) {
	for i := range result.Records {
		r := &result.Records[i]
		email := strings.Join(r.Email, ", ")
		username := strings.Join(r.Username, ", ")
		name := strings.Join(r.Name, ", ")
		fmt.Fprintf(w, "%s %s %s %s %s\n", email, username, name, r.Database, r.ObtainedDate)
	}
}

func outputDehashedJSONLForTest(w *bytes.Buffer, result *DomainResult) {
	type dehashedJSON struct {
		Type         string   `json:"type"`
		Domain       string   `json:"domain"`
		ID           string   `json:"id,omitempty"`
		Email        []string `json:"email,omitempty"`
		Username     []string `json:"username,omitempty"`
		Name         []string `json:"name,omitempty"`
		IPAddress    []string `json:"ip_address,omitempty"`
		Phone        []string `json:"phone,omitempty"`
		Address      []string `json:"address,omitempty"`
		DOB          []string `json:"dob,omitempty"`
		Database     string   `json:"database,omitempty"`
		ObtainedDate string   `json:"obtained_date,omitempty"`
	}
	enc := json.NewEncoder(w)
	for i := range result.Records {
		r := &result.Records[i]
		jr := dehashedJSON{
			Type:         "dehashed",
			Domain:       result.Domain,
			ID:           r.ID,
			Email:        r.Email,
			Username:     r.Username,
			Name:         r.Name,
			IPAddress:    r.IPAddress,
			Phone:        r.Phone,
			Address:      r.Address,
			DOB:          r.DOB,
			Database:     r.Database,
			ObtainedDate: r.ObtainedDate,
		}
		_ = enc.Encode(jr)
	}
}

func TestSearch_DropsCredentials(t *testing.T) {
	// The mock API response deliberately includes password and hashed_password
	// fields alongside the identity fields we DO collect.
	apiResp := `{
		"balance": 9000,
		"total": 1,
		"took": "1ms",
		"entries": [{
			"id": "cred-entry-1",
			"email": ["alice@example.com"],
			"username": ["alice"],
			"name": ["Alice Smith"],
			"ip_address": ["1.2.3.4"],
			"phone": [],
			"address": [],
			"dob": [],
			"database_name": "breach-db",
			"obtained_date": "2021-01",
			"password": ["secret123"],
			"hashed_password": ["abc...hashedvalue"]
		}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(apiResp))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	result, err := c.Search(context.Background(), "example.com", 0)
	require.NoError(t, err)
	require.Len(t, result.Records, 1)

	rec := result.Records[0]

	// --- Assert identity fields ARE present ---
	assert.Equal(t, []string{"alice@example.com"}, rec.Email)
	assert.Equal(t, []string{"alice"}, rec.Username)
	assert.Equal(t, []string{"Alice Smith"}, rec.Name)

	// --- Assert credential fields NEVER appear in Record struct ---
	// Record has no Password or HashedPassword fields by design (P0-SCOPE).
	// Verify via JSON round-trip: marshal the record and check no cred keys appear.
	recBytes, err := json.Marshal(rec)
	require.NoError(t, err)
	recJSON := strings.ToLower(string(recBytes))
	assert.NotContains(t, recJSON, "secret123", "credential value must not appear in Record JSON")
	assert.NotContains(t, recJSON, "abc...hashedvalue", "hashed credential must not appear in Record JSON")
	assert.NotContains(t, recJSON, "password", "no password key must appear in Record JSON")

	// --- Assert credential values NEVER appear in human output ---
	var humanBuf bytes.Buffer
	outputDehashedHumanForTest(&humanBuf, result)
	humanOut := humanBuf.String()
	assert.NotContains(t, humanOut, "secret123", "credential value must not appear in human output")
	assert.NotContains(t, humanOut, "abc...hashedvalue", "hashed credential must not appear in human output")
	assert.NotContains(t, strings.ToLower(humanOut), "password", "password key must not appear in human output")

	// --- Assert credential values NEVER appear in JSONL output ---
	var jsonlBuf bytes.Buffer
	outputDehashedJSONLForTest(&jsonlBuf, result)
	jsonlOut := jsonlBuf.String()
	assert.NotContains(t, jsonlOut, "secret123", "credential value must not appear in JSONL output")
	assert.NotContains(t, jsonlOut, "abc...hashedvalue", "hashed credential must not appear in JSONL output")
	assert.NotContains(t, strings.ToLower(jsonlOut), "hashed_password", "hashed_password key must not appear in JSONL output")
	assert.NotContains(t, strings.ToLower(jsonlOut), `"password"`, "password key must not appear in JSONL output")
}

// ---------------------------------------------------------------------------
// Task A: TestRefine — table-driven coverage of Refine()
// ---------------------------------------------------------------------------

func TestRefine(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
		opts    RefineOptions
		check   func(t *testing.T, got []Entry)
	}{
		// ----- CorporateOnly -----
		{
			name: "CorporateOnly: keeps @domain email, drops @gmail.com email",
			records: []Record{
				{Email: []string{"alice@fox.com"}, Name: []string{"Alice"}, Database: "DB1"},
				{Email: []string{"bob@gmail.com"}, Name: []string{"Bob"}, Database: "DB2"},
			},
			opts: RefineOptions{Domain: "fox.com", CorporateOnly: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				assert.Equal(t, "alice@fox.com", got[0].Email)
			},
		},
		{
			name: "CorporateOnly: case-insensitive domain match (FOX.COM vs fox.com)",
			records: []Record{
				{Email: []string{"alice@FOX.COM"}, Database: "DB1"},
			},
			opts: RefineOptions{Domain: "fox.com", CorporateOnly: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				assert.Equal(t, "alice@FOX.COM", got[0].Email)
			},
		},
		{
			name: "CorporateOnly false: keeps @gmail.com",
			records: []Record{
				{Email: []string{"bob@gmail.com"}, Database: "DB1"},
			},
			opts: RefineOptions{Domain: "fox.com", CorporateOnly: false},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				assert.Equal(t, "bob@gmail.com", got[0].Email)
			},
		},
		// ----- Dedup merge -----
		{
			name: "Dedup: two records with same email → one Entry, Count=2, databases merged",
			records: []Record{
				{Email: []string{"alice@example.com"}, Name: []string{"Alice"}, Username: []string{"alice1"}, Phone: []string{"+1-555-0100"}, Database: "DB-A"},
				{Email: []string{"alice@example.com"}, Name: []string{"Alice Smith"}, Username: []string{"a.smith"}, Phone: []string{"+1-555-0200"}, Database: "DB-B"},
			},
			opts: RefineOptions{Domain: "example.com", Dedup: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				e := got[0]
				assert.Equal(t, "alice@example.com", e.Email)
				assert.Equal(t, 2, e.Count)
				assert.ElementsMatch(t, []string{"DB-A", "DB-B"}, e.Databases)
				// Names from both records merged
				assert.ElementsMatch(t, []string{"Alice", "Alice Smith"}, e.Names)
				// Usernames from both records merged
				assert.ElementsMatch(t, []string{"alice1", "a.smith"}, e.Usernames)
				// Phones from both records merged — cross-breach phone union
				assert.ElementsMatch(t, []string{"+1-555-0100", "+1-555-0200"}, e.Phones)
			},
		},
		{
			name: "Dedup: empty strings dropped during union",
			records: []Record{
				{Email: []string{"alice@example.com"}, Name: []string{"", "Alice"}, Database: "DB-A"},
				{Email: []string{"alice@example.com"}, Name: []string{"Alice", ""}, Database: "DB-B"},
			},
			opts: RefineOptions{Domain: "example.com", Dedup: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				// Empty string must be dropped from Names
				assert.Equal(t, []string{"Alice"}, got[0].Names)
			},
		},
		{
			name: "Dedup: duplicate names de-duplicated across records",
			records: []Record{
				{Email: []string{"carol@example.com"}, Name: []string{"Carol"}, Phone: []string{"+44-7000-000001"}, Database: "DB-X"},
				{Email: []string{"carol@example.com"}, Name: []string{"Carol"}, Phone: []string{"+44-7000-000002"}, Database: "DB-Y"},
			},
			opts: RefineOptions{Domain: "example.com", Dedup: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				// Name appears in both — must deduplicate to one occurrence
				assert.Equal(t, []string{"Carol"}, got[0].Names)
				// Phones are distinct — both must appear
				assert.ElementsMatch(t, []string{"+44-7000-000001", "+44-7000-000002"}, got[0].Phones)
			},
		},
		// ----- ExcludeCombolists -----
		{
			name: "ExcludeCombolists: Naz.API dropped",
			records: []Record{
				{Email: []string{"x@example.com"}, Database: "Naz.API"},
			},
			opts: RefineOptions{Domain: "example.com", ExcludeCombolists: true},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name: "ExcludeCombolists: ALIEN TXTBASE dropped",
			records: []Record{
				{Email: []string{"x@example.com"}, Database: "ALIEN TXTBASE"},
			},
			opts: RefineOptions{Domain: "example.com", ExcludeCombolists: true},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name: "ExcludeCombolists: Collection #2 dropped (substring match)",
			records: []Record{
				{Email: []string{"x@example.com"}, Database: "Collection #2"},
			},
			opts: RefineOptions{Domain: "example.com", ExcludeCombolists: true},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name: "ExcludeCombolists: Exploit.in dropped",
			records: []Record{
				{Email: []string{"x@example.com"}, Database: "Exploit.in"},
			},
			opts: RefineOptions{Domain: "example.com", ExcludeCombolists: true},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name: "ExcludeCombolists: Adobe kept (real breach, not combolist)",
			records: []Record{
				{Email: []string{"x@example.com"}, Database: "Adobe"},
			},
			opts: RefineOptions{Domain: "example.com", ExcludeCombolists: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				assert.Equal(t, "x@example.com", got[0].Email)
			},
		},
		// ----- All opts false = passthrough -----
		{
			name: "All opts false: @gmail kept, no dedup, combolists kept, Count=1",
			records: []Record{
				{Email: []string{"bob@gmail.com"}, Database: "Naz.API"},
				{Email: []string{"bob@gmail.com"}, Database: "Adobe"},
			},
			opts: RefineOptions{},
			check: func(t *testing.T, got []Entry) {
				// Two separate entries (no dedup), both kept
				require.Len(t, got, 2)
				for _, e := range got {
					assert.Equal(t, 1, e.Count)
				}
				assert.Equal(t, "bob@gmail.com", got[0].Email)
				assert.Equal(t, "bob@gmail.com", got[1].Email)
			},
		},
		// ----- Edge cases -----
		{
			name:    "Empty input → empty output",
			records: []Record{},
			opts:    RefineOptions{},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name:    "Nil input → empty output",
			records: nil,
			opts:    RefineOptions{},
			check: func(t *testing.T, got []Entry) {
				assert.Empty(t, got)
			},
		},
		{
			name: "Record with no email and CorporateOnly=false → kept with Email=''",
			records: []Record{
				{Name: []string{"Ghost"}, Database: "some-db"},
			},
			opts: RefineOptions{CorporateOnly: false},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 1)
				assert.Equal(t, "", got[0].Email)
			},
		},
		{
			name: "Record with multiple emails uses first @domain email when CorporateOnly",
			records: []Record{
				{Email: []string{"personal@gmail.com", "work@fox.com", "also@fox.com"}, Database: "DB1"},
			},
			opts: RefineOptions{Domain: "fox.com", CorporateOnly: true},
			check: func(t *testing.T, got []Entry) {
				// Only one Entry emitted (does not double-emit for second @fox.com)
				require.Len(t, got, 1)
				assert.Equal(t, "work@fox.com", got[0].Email)
			},
		},
		{
			name: "Order preserved: first-seen email order with Dedup",
			records: []Record{
				{Email: []string{"beta@example.com"}, Database: "DB1"},
				{Email: []string{"alpha@example.com"}, Database: "DB2"},
				{Email: []string{"beta@example.com"}, Database: "DB3"},
			},
			opts: RefineOptions{Domain: "example.com", Dedup: true},
			check: func(t *testing.T, got []Entry) {
				require.Len(t, got, 2)
				assert.Equal(t, "beta@example.com", got[0].Email)
				assert.Equal(t, "alpha@example.com", got[1].Email)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Refine(tc.records, tc.opts)
			tc.check(t, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Task B: TestIsCombolist
// ---------------------------------------------------------------------------

func TestIsCombolist(t *testing.T) {
	// Every entry in combolistDatabases must match itself (exact) and a variation.
	for _, entry := range combolistDatabases {
		t.Run("matches denylist entry: "+entry, func(t *testing.T) {
			assert.True(t, isCombolist(entry), "expected %q to match combolist denylist", entry)
			// Case-insensitive: upper-case variant must also match.
			assert.True(t, isCombolist(strings.ToUpper(entry)),
				"expected upper-case %q to match combolist denylist (case-insensitive)", entry)
		})
	}

	// Substring match: "Collection #1 (part of a set)" contains "Collection"
	t.Run("substring match: Collection #1 (part of a set)", func(t *testing.T) {
		assert.True(t, isCombolist("Collection #1 (part of a set)"))
	})

	// Real breaches must NOT match.
	realBreaches := []string{
		"Adobe",
		"LinkedIn",
		"Dropbox",
		"MyFitnessPal",
		"Canva",
	}
	for _, db := range realBreaches {
		t.Run("does not match real breach: "+db, func(t *testing.T) {
			assert.False(t, isCombolist(db), "expected real breach %q NOT to match combolist denylist", db)
		})
	}
}

// ---------------------------------------------------------------------------
// Task 3: Search pagination
// ---------------------------------------------------------------------------

// makePagedServer builds an httptest server that serves DeHashed-shaped POST
// responses. It reads the page number from the decoded JSON body (not a query
// param — DeHashed uses POST with JSON body). An atomic counter tracks calls.
func makePagedServer(t *testing.T, allEntries []apiEntry, total, pageSize int, midErr429AtPage int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		var req searchRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		if midErr429AtPage > 0 && req.Page >= midErr429AtPage {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit"}`))
			return
		}

		start := (req.Page - 1) * pageSize
		end := start + pageSize
		if start >= len(allEntries) {
			// Return empty entries page.
			resp := searchResponse{Balance: 100, Total: total}
			b, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		if end > len(allEntries) {
			end = len(allEntries)
		}

		resp := searchResponse{
			Balance: 100,
			Total:   total,
			Took:    "1ms",
			Entries: allEntries[start:end],
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))

	return srv, &requestCount
}

func makeEntry(email string) apiEntry {
	return apiEntry{
		ID:       email,
		Email:    []string{email},
		Database: "test-db",
	}
}

func TestSearch_Pagination(t *testing.T) {
	tests := []struct {
		name            string
		allEntries      []apiEntry
		total           int
		pageSize        int
		limit           int
		midErr429AtPage int
		wantRecords     int
		wantRequests    int32
		wantErr         error
	}{
		{
			name:         "single page — 3 entries total",
			allEntries:   []apiEntry{makeEntry("a@e.com"), makeEntry("b@e.com"), makeEntry("c@e.com")},
			total:        3,
			pageSize:     10,
			limit:        0,
			wantRecords:  3,
			wantRequests: 1, // page 1 returns all 3; len(records)>=total stops loop
		},
		{
			name: "two full pages plus short final — pageSize 2, total 5",
			allEntries: []apiEntry{
				makeEntry("a@e.com"), makeEntry("b@e.com"),
				makeEntry("c@e.com"), makeEntry("d@e.com"),
				makeEntry("e@e.com"),
			},
			total:        5,
			pageSize:     2,
			limit:        0,
			wantRecords:  5,
			wantRequests: 3, // page1:2, page2:2, page3:1 → total==5 reached
		},
		{
			name:         "empty domain — zero records",
			allEntries:   []apiEntry{},
			total:        0,
			pageSize:     10,
			limit:        0,
			wantRecords:  0,
			wantRequests: 1, // single request returns empty entries
		},
		{
			name: "limit truncation — stops after limit reached",
			allEntries: []apiEntry{
				makeEntry("a@e.com"), makeEntry("b@e.com"),
				makeEntry("c@e.com"), makeEntry("d@e.com"),
				makeEntry("e@e.com"),
			},
			total:        5,
			pageSize:     10,
			limit:        3,
			wantRecords:  3,
			wantRequests: 1, // all 5 fit in 1 page, limit truncates to 3
		},
		{
			name: "mid-pagination 429 → ErrRateLimited",
			allEntries: []apiEntry{
				makeEntry("a@e.com"), makeEntry("b@e.com"),
				makeEntry("c@e.com"),
			},
			total:           3,
			pageSize:        2,
			limit:           0,
			midErr429AtPage: 2,
			wantErr:         ErrRateLimited,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, reqCount := makePagedServer(t, tc.allEntries, tc.total, tc.pageSize, tc.midErr429AtPage)
			defer srv.Close()

			c := newTestClient(srv.URL)
			c.pageSize = tc.pageSize

			result, err := c.Search(context.Background(), "example.com", tc.limit)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "expected %v, got %v", tc.wantErr, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantRecords, len(result.Records))
			assert.Equal(t, tc.wantRequests, reqCount.Load())
		})
	}
}

// ---------------------------------------------------------------------------
// Task 4: Context cancellation
// ---------------------------------------------------------------------------

func TestSearch_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow server: block longer than the context deadline.
		time.Sleep(200 * time.Millisecond)
		resp := searchResponse{
			Balance: 100,
			Total:   1000,
			Entries: []apiEntry{makeEntry("user@example.com")},
		}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.pageSize = 1

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Search(ctx, "example.com", 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Task 5: do() — auth header and URL safety
// ---------------------------------------------------------------------------

func TestDo_SetsAuthHeader(t *testing.T) {
	const testKey = "super-secret-key-xyz"
	var capturedHeader string
	var capturedURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get(headerAPIKey)
		capturedURL = r.URL.String()
		resp := searchResponse{Balance: 100, Total: 0}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := NewClient(testKey, 5*time.Second, 10)
	c.baseURL = srv.URL

	_, _ = c.do(context.Background(), searchRequest{Query: "domain:example.com", Size: 10, Page: 1})

	// Key must appear in the Dehashed-Api-Key header.
	assert.Equal(t, testKey, capturedHeader)
	// Key must NOT appear in the URL (P0-1).
	assert.NotContains(t, capturedURL, testKey)
}

// ---------------------------------------------------------------------------
// Task 6: do() — malformed JSON returns decode error
// ---------------------------------------------------------------------------

func TestDo_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	_, _, err := func() (*DomainResult, bool, error) {
		result, err := c.Search(context.Background(), "example.com", 0)
		return result, false, err
	}()
	// Search calls do then json.Unmarshal; malformed JSON surfaces as a decode error.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding dehashed response")
}
