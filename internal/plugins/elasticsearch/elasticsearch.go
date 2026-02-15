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
	"crypto/tls"
	"fmt"
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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "elasticsearch",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build URL for cluster info endpoint
	url := fmt.Sprintf("http://%s/", target)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Set Basic Auth
	req.SetBasicAuth(username, password)

	// Create HTTP client with timeout and TLS config to skip cert verification
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusUnauthorized {
		// Authentication failed - this is expected for invalid credentials
		result.Success = false
		result.Error = nil // Auth failure returns nil error
		result.Duration = time.Since(start)
		return result
	}

	if resp.StatusCode == http.StatusOK {
		// Success - valid credentials
		result.Success = true
		result.Error = nil
		result.Duration = time.Since(start)
		return result
	}

	// Any other status code is a connection/server error
	result.Success = false
	result.Error = fmt.Errorf("connection error: unexpected status code %d", resp.StatusCode)
	result.Duration = time.Since(start)
	return result
}
