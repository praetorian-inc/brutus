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

// pkg/enum/harvest/sources/duckduckgo.go
package sources

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	ddgName            = "ddg"
	defaultDDGEndpoint = "https://html.duckduckgo.com/html/"
	ddgPageSize        = 30
)

func init() {
	harvest.Register(ddgName, func(c *http.Client) harvest.Source { return newDDG(c) })
}

// ddg harvests emails by scraping the DuckDuckGo html endpoint.
type ddg struct {
	client   *http.Client
	endpoint string
}

func newDDG(c *http.Client) *ddg {
	return &ddg{client: c, endpoint: defaultDDGEndpoint}
}

// newDDGWithEndpoint overrides the endpoint for tests (httptest server URL).
func newDDGWithEndpoint(c *http.Client, endpoint string) *ddg {
	return &ddg{client: c, endpoint: endpoint}
}

func (d *ddg) Name() string { return ddgName }

func (d *ddg) Search(ctx context.Context, domain string) ([]string, error) {
	cfg := serpConfig{
		name:     ddgName,
		client:   d.client,
		endpoint: d.endpoint,
		pageSize: ddgPageSize,
		maxPages: serpMaxPages,
		buildURL: func(endpoint, query string, page int) string {
			q := url.Values{
				"q": {query},
				"s": {strconv.Itoa(page * ddgPageSize)},
			}
			return endpoint + "?" + q.Encode()
		},
	}
	return fetchSERP(ctx, cfg, domain)
}
