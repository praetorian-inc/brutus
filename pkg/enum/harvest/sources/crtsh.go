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

// pkg/enum/harvest/sources/crtsh.go
package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
)

const (
	crtshName            = "crtsh"
	defaultCrtshEndpoint = "https://crt.sh/"
	// crtshBodyCap bounds the crt.sh JSON read (security P0-3). crt.sh responses
	// for popular domains legitimately exceed the 1 MB default, so the cap is
	// raised to 16 MB; the body is still bounded against a hostile endpoint.
	crtshBodyCap int64 = 16 << 20
)

func init() {
	harvest.Register(crtshName, func(c *http.Client) harvest.Source { return newCrtsh(c) })
}

// crtsh harvests emails from crt.sh Certificate Transparency search.
type crtsh struct {
	client   *http.Client
	endpoint string
}

func newCrtsh(c *http.Client) *crtsh {
	return &crtsh{client: c, endpoint: defaultCrtshEndpoint}
}

// newCrtshWithEndpoint overrides the endpoint for tests (httptest server URL).
func newCrtshWithEndpoint(c *http.Client, endpoint string) *crtsh {
	return &crtsh{client: c, endpoint: endpoint}
}

func (c *crtsh) Name() string { return crtshName }

// Search queries crt.sh for the domain and returns only emails (any host/name
// fields in the JSON are not emails and are dropped by the extractor's
// domain-anchoring). The domain appears only in an escaped query value; the host
// comes from the hardcoded endpoint constant (security P0-1).
func (c *crtsh) Search(ctx context.Context, domain string) ([]string, error) {
	q := url.Values{
		"q":      {"%." + domain},
		"output": {"json"},
	}
	rawURL := c.endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building crtsh request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := enum.ReadResponseBody(resp, crtshBodyCap)
	if err != nil {
		return nil, fmt.Errorf("reading crtsh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh returned HTTP %d", resp.StatusCode)
	}

	return harvest.ExtractEmails(string(body), domain, true), nil
}
