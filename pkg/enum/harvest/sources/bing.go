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

// pkg/enum/harvest/sources/bing.go
package sources

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	bingName            = "bing"
	defaultBingEndpoint = "https://www.bing.com/search"
	bingPageSize        = 10
)

func init() {
	harvest.Register(bingName, func(c *http.Client) harvest.Source { return newBing(c) })
}

// bing harvests emails by scraping Bing SERP HTML.
type bing struct {
	client   *http.Client
	endpoint string
}

func newBing(c *http.Client) *bing {
	return &bing{client: c, endpoint: defaultBingEndpoint}
}

// newBingWithEndpoint overrides the endpoint for tests (httptest server URL).
func newBingWithEndpoint(c *http.Client, endpoint string) *bing {
	return &bing{client: c, endpoint: endpoint}
}

func (b *bing) Name() string { return bingName }

func (b *bing) Search(ctx context.Context, domain string) ([]string, error) {
	cfg := serpConfig{
		name:     bingName,
		client:   b.client,
		endpoint: b.endpoint,
		pageSize: bingPageSize,
		maxPages: serpMaxPages,
		buildURL: func(endpoint, query string, page int) string {
			q := url.Values{
				"q":     {query},
				"first": {strconv.Itoa(page*bingPageSize + 1)},
			}
			return endpoint + "?" + q.Encode()
		},
	}
	return fetchSERP(ctx, cfg, domain)
}
