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

// pkg/enum/harvest/sources/serp.go
package sources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	// serpMaxPages is the polite per-source page cap shared by all SERP scrapers.
	serpMaxPages = 3
	// serpBodyCap bounds each SERP HTML read (security P0-3). SERP pages can
	// exceed the 1 MB default; 4 MB captures the result region while still
	// bounding memory against a hostile endpoint.
	serpBodyCap int64 = 4 << 20
)

// serpConfig parameterizes a search-engine scraper. The four SERP sources
// (Bing/DuckDuckGo/Brave/Yahoo) differ only in name, endpoint, page size, and
// URL builder — extracted here at the fourth occurrence (Rule of Three).
type serpConfig struct {
	name     string
	client   *http.Client
	endpoint string
	pageSize int
	maxPages int
	// buildURL returns the request URL for the quoted query and zero-based page.
	buildURL func(endpoint, query string, page int) string
}

// fetchSERP runs the quoted "@domain" query across pages, extracting emails via
// harvest.ExtractEmails and deduping across pages. It stops on a short/empty page,
// reaching maxPages, or ctx cancellation. Per-request bodies are size-capped
// (security P0-3); the domain is carried only inside the engine-built query value.
func fetchSERP(ctx context.Context, cfg serpConfig, domain string) ([]string, error) {
	query := `"@` + domain + `"`

	seen := make(map[string]struct{})
	var out []string

	for page := 0; page < cfg.maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return out, nil
		}

		rawURL := cfg.buildURL(cfg.endpoint, query, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("building %s request: %w", cfg.name, err)
		}

		resp, err := cfg.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s request failed: %w", cfg.name, err)
		}
		body, readErr := enum.ReadResponseBody(resp, serpBodyCap)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading %s response: %w", cfg.name, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s returned HTTP %d", cfg.name, resp.StatusCode)
		}

		pageEmails := harvest.ExtractEmails(string(body), domain, true)
		for _, e := range pageEmails {
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = struct{}{}
			out = append(out, e)
		}

		// Stop on a short/empty page: fewer than a full page of results means
		// there is no next page worth fetching.
		if len(pageEmails) < cfg.pageSize {
			break
		}
	}

	return out, nil
}
