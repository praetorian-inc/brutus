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

// Package google provides Google Workspace account enumeration.
package google

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

func init() {
	enum.Register("google", func() enum.Plugin {
		return &Plugin{
			accountChooserBaseURL: "https://accounts.google.com",
			gxluBaseURL:           "https://mail.google.com",
		}
	})
}

// Plugin checks Google Workspace account existence using AccountChooser SSO and GXLU.
type Plugin struct {
	accountChooserBaseURL string // base URL for AccountChooser (overridable for testing)
	gxluBaseURL           string // base URL for GXLU (overridable for testing)
}

func (p *Plugin) Name() string { return "google" }

func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	// Try AccountChooser SSO redirect (primary — detects Workspace accounts with SSO)
	exists, err := p.checkAccountChooser(ctx, email, timeout)
	if err == nil && exists {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
		result.Duration = time.Since(start)
		return result
	}

	// Try GXLU (detects Gmail-enabled accounts)
	exists, err = p.checkGXLU(ctx, email, timeout)
	if err == nil && exists {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
		result.Duration = time.Since(start)
		return result
	}

	// Neither method confirmed existence
	result.Exists = false
	result.Confidence = enum.ConfidenceMedium
	result.Duration = time.Since(start)
	return result
}

// checkAccountChooser checks if Google redirects to a SAML IdP for this email.
// SSO-configured domains redirect valid accounts to their IdP; invalid accounts
// redirect back to accounts.google.com/ServiceLogin.
func (p *Plugin) checkAccountChooser(ctx context.Context, email string, timeout time.Duration) (bool, error) {
	u := p.accountChooserBaseURL + "/AccountChooser?Email=" + url.QueryEscape(email) + "&continue=https://mail.google.com/mail/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, fmt.Errorf("creating AccountChooser request: %w", err)
	}

	client := enum.NewEnumHTTPClient(timeout)
	// Don't follow redirects — we need to inspect the 302 Location header
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("AccountChooser request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check for SAML redirect header — present only for valid accounts on SSO domains
	if resp.Header.Get("Google-Accounts-SAML") != "" {
		return true, nil
	}

	// Also check: if Location redirects to a non-Google host, it's an IdP redirect
	location := resp.Header.Get("Location")
	if location != "" && !strings.Contains(location, "accounts.google.com") && !strings.Contains(location, "google.com/ServiceLogin") {
		return true, nil
	}

	return false, nil
}

// checkGXLU checks if an email has a Gmail-enabled Google account.
// GET https://mail.google.com/mail/gxlu?email=USER@DOMAIN
// If response contains GMAIL_AT cookie → account exists.
func (p *Plugin) checkGXLU(ctx context.Context, email string, timeout time.Duration) (bool, error) {
	gxluURL := p.gxluBaseURL + "/mail/gxlu?email=" + url.QueryEscape(email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gxluURL, nil)
	if err != nil {
		return false, fmt.Errorf("creating GXLU request: %w", err)
	}

	client := enum.NewEnumHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("GXLU request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check for GMAIL_AT cookie — its presence indicates the account exists
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "GMAIL_AT" {
			return true, nil
		}
	}

	return false, nil
}
