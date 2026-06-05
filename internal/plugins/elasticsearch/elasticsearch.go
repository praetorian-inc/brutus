// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elasticsearch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("elasticsearch", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Elasticsearch password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "elasticsearch"
}

// Test attempts Elasticsearch password authentication using HTTP Basic Auth.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials (200 OK)
// - Success=false, Error=nil: Invalid credentials (401 Unauthorized)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("elasticsearch", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode

	scheme := brutus.SchemeFromTLSMode(tlsMode)

	// Build URL for cluster info endpoint
	url := fmt.Sprintf("%s://%s/", scheme, target)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	// Set Basic Auth
	req.SetBasicAuth(username, password)

	// Create HTTP client with TLS config (proxy-aware)
	client, err := brutus.NewHTTPClientWithProxy(timeout, brutus.BuildTLSConfig(tlsMode), pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode == http.StatusUnauthorized {
		// Authentication failed - this is expected for invalid credentials
		result.Success = false
		result.Error = nil // Auth failure returns nil error
		return result
	}

	if resp.StatusCode == http.StatusOK {
		// Success - valid credentials
		result.Success = true
		result.Error = nil
		return result
	}

	// Any other status code is a connection/server error
	result.Success = false
	result.Error = fmt.Errorf("connection error: unexpected status code %d", resp.StatusCode)
	return result
}

// CheckUnauth probes for Elasticsearch without security enabled (X-Pack).
func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("elasticsearch", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	scheme := brutus.SchemeFromTLSMode(pluginCfg.TLSMode)
	url := fmt.Sprintf("%s://%s/", scheme, target)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return result
	}
	// Intentionally no Basic Auth header

	client, err := brutus.NewHTTPClientWithProxy(timeout, brutus.BuildTLSConfig(pluginCfg.TLSMode), pluginCfg.ProxyURL)
	if err != nil {
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bannerText := "[CRITICAL] Elasticsearch accessible without authentication"
	if len(bodyBytes) > 0 {
		bannerText += fmt.Sprintf("\nCluster info: %s", string(bodyBytes))
	}

	result.Success = true
	result.Banner = bannerText
	return result
}
