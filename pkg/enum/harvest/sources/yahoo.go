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

// pkg/enum/harvest/sources/yahoo.go
package sources

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	yahooName            = "yahoo"
	defaultYahooEndpoint = "https://search.yahoo.com/search"
	yahooPageSize        = 10
)

func init() {
	harvest.Register(yahooName, func(c *http.Client) harvest.Source { return newYahoo(c) })
}

// yahoo harvests emails by scraping Yahoo Search SERP HTML.
type yahoo struct {
	client   *http.Client
	endpoint string
}

func newYahoo(c *http.Client) *yahoo {
	return &yahoo{client: c, endpoint: defaultYahooEndpoint}
}

// newYahooWithEndpoint overrides the endpoint for tests (httptest server URL).
func newYahooWithEndpoint(c *http.Client, endpoint string) *yahoo {
	return &yahoo{client: c, endpoint: endpoint}
}

func (y *yahoo) Name() string { return yahooName }

func (y *yahoo) Search(ctx context.Context, domain string) ([]string, error) {
	cfg := serpConfig{
		name:     yahooName,
		client:   y.client,
		endpoint: y.endpoint,
		pageSize: yahooPageSize,
		maxPages: serpMaxPages,
		buildURL: func(endpoint, query string, page int) string {
			q := url.Values{
				"p": {query},
				"b": {strconv.Itoa(page*yahooPageSize + 1)},
			}
			return endpoint + "?" + q.Encode()
		},
	}
	return fetchSERP(ctx, cfg, domain)
}
