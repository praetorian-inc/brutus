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

// pkg/enum/harvest/sources/brave.go
package sources

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	braveName            = "brave"
	defaultBraveEndpoint = "https://search.brave.com/search"
	bravePageSize        = 10
)

func init() {
	harvest.Register(braveName, func(c *http.Client) harvest.Source { return newBrave(c) })
}

// brave harvests emails by scraping Brave Search SERP HTML.
type brave struct {
	client   *http.Client
	endpoint string
}

func newBrave(c *http.Client) *brave {
	return &brave{client: c, endpoint: defaultBraveEndpoint}
}

// newBraveWithEndpoint overrides the endpoint for tests (httptest server URL).
func newBraveWithEndpoint(c *http.Client, endpoint string) *brave {
	return &brave{client: c, endpoint: endpoint}
}

func (b *brave) Name() string { return braveName }

func (b *brave) Search(ctx context.Context, domain string) ([]string, error) {
	cfg := serpConfig{
		name:     braveName,
		client:   b.client,
		endpoint: b.endpoint,
		pageSize: bravePageSize,
		maxPages: serpMaxPages,
		buildURL: func(endpoint, query string, page int) string {
			q := url.Values{
				"q":      {query},
				"offset": {strconv.Itoa(page)},
			}
			return endpoint + "?" + q.Encode()
		},
	}
	return fetchSERP(ctx, cfg, domain)
}
