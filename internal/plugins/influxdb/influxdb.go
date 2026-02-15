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

package influxdb

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("influxdb", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements InfluxDB password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "influxdb"
}

// Test attempts InfluxDB password authentication using HTTP Basic Auth.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "influxdb",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build InfluxDB signin endpoint URL
	// POST /api/v2/signin accepts HTTP Basic Auth for username/password authentication
	// Returns 204 No Content on success, 401 Unauthorized on failure
	url := fmt.Sprintf("http://%s/api/v2/signin", target)

	// Create HTTP POST request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Set HTTP Basic Auth
	req.SetBasicAuth(username, password)

	// Create HTTP client with timeout and TLS config to skip cert verification
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Send HTTP request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	// Classify response
	if resp.StatusCode == http.StatusUnauthorized {
		// 401 Unauthorized = authentication failure
		result.Success = false
		result.Error = nil
		result.Duration = time.Since(start)
		return result
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		// 200 OK or 204 No Content = success
		result.Success = true
		result.Error = nil
		result.Duration = time.Since(start)
		return result
	}

	// Any other status code is a connection error
	result.Error = fmt.Errorf("connection error: unexpected status code %d", resp.StatusCode)
	result.Duration = time.Since(start)
	return result
}
