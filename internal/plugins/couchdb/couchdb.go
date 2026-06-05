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

package couchdb

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("couchdb", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements CouchDB password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "couchdb"
}

// Test attempts CouchDB password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("couchdb", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode

	scheme := brutus.SchemeFromTLSMode(tlsMode)

	// Build URL for CouchDB session endpoint
	url := fmt.Sprintf("%s://%s/_session", scheme, target)

	// Create HTTP client with TLS config
	client, err := brutus.NewHTTPClientWithProxy(timeout, brutus.BuildTLSConfig(tlsMode), pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	// Set Basic Auth
	req.SetBasicAuth(username, password)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	// Classify response
	if resp.StatusCode == http.StatusOK {
		// Success - valid credentials
		result.Success = true
		return result
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Auth failure - invalid credentials
		// Return Success=false, Error=nil
		return result
	}

	// All other status codes are connection/server errors
	result.Error = fmt.Errorf("connection error: HTTP %d", resp.StatusCode)
	return result
}
