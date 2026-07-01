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

// Package okta provides passive Okta tenant discovery for a given email domain.
// It probes the well-known OpenID configuration endpoint on the candidate
// <slug>.okta.com subdomain to determine whether the target organization has an
// Okta tenant. No authentication attempts are made.
package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"golang.org/x/net/publicsuffix"
)

const DefaultBaseURL = "https://%s.okta.com"

// Result is the outcome of probing for an Okta tenant associated with an
// email's domain.
type Result struct {
	Email     string
	HasTenant bool
	TenantURL string
	Error     error
	Duration  time.Duration
}

// Checker probes for Okta tenant existence. It is safe for concurrent use.
type Checker struct {
	baseURLFmt string
	timeout    time.Duration
	client     *http.Client
}

// NewChecker creates a Checker. Pass "" for baseURLFmt to use the default
// Okta subdomain pattern (https://%s.okta.com). The format string must contain
// exactly one %s verb for the tenant slug.
func NewChecker(baseURLFmt string, timeout time.Duration) *Checker {
	if baseURLFmt == "" {
		baseURLFmt = DefaultBaseURL
	}
	return &Checker{
		baseURLFmt: baseURLFmt,
		timeout:    timeout,
		client:     enum.NewEnumHTTPClient(timeout),
	}
}

// oidcConfig is the subset of the OpenID Connect discovery document we inspect.
type oidcConfig struct {
	Issuer string `json:"issuer"`
}

// CheckTenant probes whether the email's domain has an Okta tenant by hitting
// the well-known OpenID configuration endpoint on <slug>.okta.com. The slug is
// derived from the domain's first label (e.g. "acme" from "acme.co.uk").
func (c *Checker) CheckTenant(ctx context.Context, email string) *Result {
	start := time.Now()
	result := &Result{Email: email}
	defer func() { result.Duration = time.Since(start) }()

	slug := slugFromEmail(email)
	if slug == "" {
		result.Error = fmt.Errorf("cannot derive tenant slug from email %q", email)
		return result
	}

	base := fmt.Sprintf(c.baseURLFmt, slug)
	url := base + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	resp, err := c.client.Do(req)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// NXDOMAIN — no such subdomain, so no tenant.
			return result
		}
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		return result
	}

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		return result
	}

	var cfg oidcConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		result.Error = fmt.Errorf("decoding response: %w", err)
		return result
	}

	if cfg.Issuer != "" {
		result.HasTenant = true
		result.TenantURL = base
	}

	return result
}

// slugFromEmail extracts the organization name from an email domain using
// the public suffix list. For "user@mail.acme.com" it returns "acme" (the
// registrable domain minus its public suffix). Falls back to the first domain
// label when the domain is itself a public suffix.
func slugFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return ""
	}
	domain := strings.ToLower(parts[1])

	// Try to extract the registrable domain (e.g. "acme.co.uk" from
	// "mail.acme.co.uk"). This strips subdomains and keeps only the
	// organization-level label plus the public suffix.
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err == nil {
		// reg is e.g. "acme.co.uk"; the org name is the first label.
		dot := strings.IndexByte(reg, '.')
		if dot > 0 {
			return reg[:dot]
		}
	}

	// Fallback: domain is itself a suffix or unparseable — use the first label.
	dot := strings.IndexByte(domain, '.')
	if dot <= 0 {
		return ""
	}
	return domain[:dot]
}
