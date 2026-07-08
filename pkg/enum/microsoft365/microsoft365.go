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

// Package microsoft365 provides O365 account enumeration via the
// GetCredentialType API. This is the single source of truth for the Microsoft
// 365 account-existence check, reused by the internal enum oracle plugin and
// consumable via the Brutus API.
package microsoft365

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const DefaultBaseURL = "https://login.microsoftonline.com"

// IfExistsResult values returned by the GetCredentialType API.
const (
	IfExistsResultExists          = 0
	IfExistsResultNotExists       = 1
	IfExistsResultDifferentTenant = 5
	IfExistsResultDomainHint      = 6
)

type credTypeRequest struct {
	Username string `json:"Username"`
}

type credTypeResponse struct {
	IfExistsResult        int    `json:"IfExistsResult"`
	ThrottleStatus        int    `json:"ThrottleStatus"`
	FederationRedirectUrl string `json:"FederationRedirectUrl,omitempty"`
}

// Result is the outcome of checking a single email against the
// GetCredentialType API.
type Result struct {
	Email          string
	Exists         bool
	IfExistsResult int
	Federated      bool
	FederationURL  string
	Error          error
	Duration       time.Duration
}

// Checker performs O365 account-existence checks via GetCredentialType. It is
// safe for concurrent use.
type Checker struct {
	baseURL string
	timeout time.Duration
	client  *http.Client
}

// NewChecker creates a Checker with the given timeout. Pass "" for baseURL to
// use the default Microsoft login endpoint. Pass "" for proxyURL for a direct
// (non-proxied) client; when proxyURL is non-empty the checker's client routes
// through it (honoring the --proxy flag), mirroring the Google enumerator.
func NewChecker(baseURL, proxyURL string, timeout time.Duration) (*Checker, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	client := enum.NewEnumHTTPClient(timeout)
	if proxyURL != "" {
		c, err := enum.NewEnumHTTPClientWithProxy(timeout, proxyURL)
		if err != nil {
			return nil, fmt.Errorf("microsoft365: configuring proxy: %w", err)
		}
		client = c
	}
	return &Checker{
		baseURL: baseURL,
		timeout: timeout,
		client:  client,
	}, nil
}

// CheckAccount tests if an email account exists on Microsoft 365 via the
// GetCredentialType API. It handles IfExistsResult codes 0/1/5/6, throttle
// detection, and federation redirect URL extraction.
//
// If ctx carries a shared enum HTTP client (via enum.WithHTTPClient — set for a
// run to honor --proxy and connection pooling), that client is used; otherwise
// the Checker's own client is used.
func (c *Checker) CheckAccount(ctx context.Context, email string) *Result {
	start := time.Now()
	result := &Result{Email: email}
	defer func() { result.Duration = time.Since(start) }()

	body, err := json.Marshal(credTypeRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		return result
	}

	url := c.baseURL + "/common/GetCredentialType"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	client := enum.HTTPClientFromContext(ctx)
	if client == nil {
		client = c.client
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		return result
	}

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		return result
	}
	var credResp credTypeResponse
	if err := json.Unmarshal(raw, &credResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		return result
	}

	if credResp.ThrottleStatus != 0 {
		result.Error = fmt.Errorf("throttled by Microsoft 365")
		return result
	}

	result.IfExistsResult = credResp.IfExistsResult

	switch credResp.IfExistsResult {
	case IfExistsResultExists, IfExistsResultDifferentTenant, IfExistsResultDomainHint:
		result.Exists = true
	}

	if credResp.FederationRedirectUrl != "" {
		result.Federated = true
		result.FederationURL = credResp.FederationRedirectUrl
	}

	return result
}
