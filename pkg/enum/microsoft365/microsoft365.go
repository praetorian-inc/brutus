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
	IfExistsResult       int    `json:"IfExistsResult"`
	ThrottleStatus       int    `json:"ThrottleStatus"`
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
}

// NewChecker creates a Checker with the given timeout. Pass "" for baseURL to
// use the default Microsoft login endpoint.
func NewChecker(baseURL string, timeout time.Duration) *Checker {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Checker{baseURL: baseURL, timeout: timeout}
}

// CheckAccount tests if an email account exists on Microsoft 365 via the
// GetCredentialType API. It handles IfExistsResult codes 0/1/5/6, throttle
// detection, and federation redirect URL extraction.
func (c *Checker) CheckAccount(ctx context.Context, email string) *Result {
	start := time.Now()
	result := &Result{Email: email}

	body, err := json.Marshal(credTypeRequest{Username: email})
	if err != nil {
		result.Error = fmt.Errorf("marshaling request: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	url := c.baseURL + "/common/GetCredentialType"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	client := enum.NewEnumHTTPClient(c.timeout)
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("request failed: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	var credResp credTypeResponse
	if err := json.Unmarshal(raw, &credResp); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	if credResp.ThrottleStatus != 0 {
		result.Error = fmt.Errorf("throttled by Microsoft 365")
		result.Duration = time.Since(start)
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

	result.Duration = time.Since(start)
	return result
}
