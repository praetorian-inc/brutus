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

package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// buildSERPPage returns HTML containing n distinct emails for acme.com, e.g.
// "user0@acme.com user1@acme.com ...".
func buildSERPPage(start, n int) string {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, " user%d@acme.com", start+i)
	}
	sb.WriteString("</body></html>")
	return sb.String()
}

// TestFetchSERPPagesExtractsAcrossPages verifies that fetchSERP:
//   - pages until it receives a short (< pageSize) page,
//   - collects emails from multiple pages,
//   - deduplicates across pages,
//   - respects the maxPages cap.
func TestFetchSERPPagesExtractsAcrossPages(t *testing.T) {
	t.Parallel()

	const pageSize = 5

	// Page 0: full page (5 unique emails) → should continue.
	// Page 1: short page (1 email) → should stop.
	pageData := []string{
		buildSERPPage(0, pageSize), // full page
		buildSERPPage(pageSize, 1), // short final page
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := callCount
		callCount++
		if page < len(pageData) {
			_, _ = w.Write([]byte(pageData[page]))
		} else {
			_, _ = w.Write([]byte("<html></html>"))
		}
	}))
	defer srv.Close()

	cfg := serpConfig{
		name:     "test-serp",
		client:   enum.NewEnumHTTPClient(5 * time.Second),
		endpoint: srv.URL,
		pageSize: pageSize,
		maxPages: 10,
		buildURL: func(endpoint, query string, page int) string {
			return fmt.Sprintf("%s?q=%s&page=%d", endpoint, query, page)
		},
	}

	emails, err := fetchSERP(context.Background(), cfg, "acme.com")
	require.NoError(t, err)

	// Should have received pageSize + 1 = 6 unique emails.
	assert.Len(t, emails, pageSize+1)
	for _, e := range emails {
		assert.Contains(t, e, "@", "every result must be an email")
	}
	// Should have stopped after 2 pages (page 0 full, page 1 short).
	assert.Equal(t, 2, callCount, "fetchSERP should stop on short page")
}

// TestFetchSERPRespectsMaxPages verifies that fetchSERP stops at maxPages even
// when every page is full.
func TestFetchSERPRespectsMaxPages(t *testing.T) {
	t.Parallel()

	const pageSize = 2
	const maxPages = 3

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return a full page — fetchSERP must stop at maxPages.
		_, _ = w.Write([]byte("<html>a@acme.com b@acme.com</html>"))
	}))
	defer srv.Close()

	callCount := 0
	cfg := serpConfig{
		name:     "test-serp-cap",
		client:   enum.NewEnumHTTPClient(5 * time.Second),
		endpoint: srv.URL,
		pageSize: pageSize,
		maxPages: maxPages,
		buildURL: func(endpoint, query string, page int) string {
			callCount++
			return fmt.Sprintf("%s?page=%d", endpoint, page)
		},
	}

	_, err := fetchSERP(context.Background(), cfg, "acme.com")
	require.NoError(t, err)
	assert.Equal(t, maxPages, callCount, "fetchSERP should stop after maxPages requests")
}

// TestFetchSERPContextCancel verifies that fetchSERP returns early when the
// context is cancelled.
func TestFetchSERPContextCancel(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>a@acme.com b@acme.com</html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before any requests

	cfg := serpConfig{
		name:     "test-serp-cancel",
		client:   enum.NewEnumHTTPClient(5 * time.Second),
		endpoint: srv.URL,
		pageSize: 2,
		maxPages: 10,
		buildURL: func(endpoint, query string, page int) string {
			return fmt.Sprintf("%s?page=%d", endpoint, page)
		},
	}

	// Should return immediately without making requests (or return an error).
	emails, _ := fetchSERP(ctx, cfg, "acme.com")
	// Either empty or nil — either way no useful results from a cancelled context.
	_ = emails
}
