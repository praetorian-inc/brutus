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
	"crypto/tls"
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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "couchdb",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build URL for CouchDB session endpoint
	url := fmt.Sprintf("http://%s/_session", target)

	// Create HTTP client with timeout and TLS config to skip cert verification
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Set Basic Auth
	req.SetBasicAuth(username, password)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	// Classify response
	if resp.StatusCode == http.StatusOK {
		// Success - valid credentials
		result.Success = true
		result.Duration = time.Since(start)
		return result
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Auth failure - invalid credentials
		// Return Success=false, Error=nil
		result.Duration = time.Since(start)
		return result
	}

	// All other status codes are connection/server errors
	result.Error = fmt.Errorf("connection error: HTTP %d", resp.StatusCode)
	result.Duration = time.Since(start)
	return result
}
