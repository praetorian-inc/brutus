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

// Package okta provides Okta tenant discovery and account enumeration.
//
// Tenant discovery: probes <slug>.okta.com/.well-known/openid-configuration
// or validates a tenant URL discovered via M365/Google federation redirects.
//
// Account enumeration: when an Okta tenant is misconfigured, /api/v1/authn
// may return distinguishable responses for valid vs. invalid usernames.
// DetectEnumeration checks for this; CheckAccount exploits it per-email.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"golang.org/x/net/publicsuffix"
)

const DefaultBaseURL = "https://%s.okta.com"

// DiscoveryMethod describes how an Okta tenant was found.
type DiscoveryMethod string

const (
	DiscoveryDirect          DiscoveryMethod = "direct"
	DiscoveryFederationM365  DiscoveryMethod = "federation-m365"
	DiscoveryFederationGoogle DiscoveryMethod = "federation-google"
)

// Result is the outcome of probing for an Okta tenant associated with an
// email's domain.
type Result struct {
	Email           string
	HasTenant       bool
	TenantURL       string
	DiscoveryMethod DiscoveryMethod
	Error           error
	Duration        time.Duration
}

// EnumSupport describes whether a tenant allows username enumeration via
// /api/v1/authn response differentiation.
type EnumSupport struct {
	Enumerable    bool
	TenantURL     string
	BaselineError string
	Error         error
}

// EnumResult is the outcome of checking a single email for existence via
// /api/v1/authn.
type EnumResult struct {
	Email    string
	Exists   bool
	Locked   bool
	Error    error
	Duration time.Duration
}

// Checker probes for Okta tenant existence and account enumeration. It is
// safe for concurrent use.
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

// ---------------------------------------------------------------------------
// Tenant discovery
// ---------------------------------------------------------------------------

// oidcConfig is the subset of the OpenID Connect discovery document we inspect.
type oidcConfig struct {
	Issuer string `json:"issuer"`
}

// CheckTenant probes whether the email's domain has an Okta tenant by hitting
// the well-known OpenID configuration endpoint on <slug>.okta.com. The slug is
// derived from the domain's first label (e.g. "acme" from "acme.co.uk").
func (c *Checker) CheckTenant(ctx context.Context, email string) *Result {
	start := time.Now()
	result := &Result{Email: email, DiscoveryMethod: DiscoveryDirect}
	defer func() { result.Duration = time.Since(start) }()

	slug := slugFromEmail(email)
	if slug == "" {
		result.Error = fmt.Errorf("cannot derive tenant slug from email %q", email)
		return result
	}

	base := fmt.Sprintf(c.baseURLFmt, slug)
	return c.probeTenantURL(ctx, result, base)
}

// CheckTenantByURL validates that tenantURL hosts an Okta tenant. Use this
// when the URL was discovered via federation redirect (M365/Google) rather
// than the slug heuristic.
func (c *Checker) CheckTenantByURL(ctx context.Context, tenantURL string, method DiscoveryMethod) *Result {
	start := time.Now()
	result := &Result{DiscoveryMethod: method}
	defer func() { result.Duration = time.Since(start) }()

	base := strings.TrimRight(tenantURL, "/")
	return c.probeTenantURL(ctx, result, base)
}

// probeTenantURL hits the .well-known/openid-configuration endpoint at the
// given base URL and populates the result.
func (c *Checker) probeTenantURL(ctx context.Context, result *Result, base string) *Result {
	oidcURL := base + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcURL, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	resp, err := c.client.Do(req)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return result
		}
		result.Error = fmt.Errorf("request failed: %w", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
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

// ---------------------------------------------------------------------------
// Account enumeration
// ---------------------------------------------------------------------------

const (
	errAuthnFailed  = "E0000004"
	errAccountLocked = "E0000002"
)

// Deliberately invalid — exists only to trigger an auth failure so we can
// compare error responses between valid and invalid usernames.
const enumProbePassword = "C4n4ry!Pr0b3#2026xQ"

// authnRequest is the body for POST /api/v1/authn.
type authnRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authnResponse covers both error and status-flow responses from /api/v1/authn.
type authnResponse struct {
	Status       string `json:"status,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorSummary string `json:"errorSummary,omitempty"`
}

type authnProbeResult struct {
	statusCode int
	response   authnResponse
	err        error
}

// indicatesExistence returns true when the authn response is a definitive
// signal that the user account exists, independent of baseline comparison.
func (r *authnProbeResult) indicatesExistence() bool {
	// Any non-error status (MFA_REQUIRED, LOCKED_OUT, PASSWORD_EXPIRED, etc.)
	// means the user was found in the directory.
	if r.response.Status != "" {
		return true
	}
	if r.response.ErrorCode == errAccountLocked {
		return true
	}
	return false
}

// DetectEnumeration probes whether the Okta tenant at tenantURL leaks username
// validity through /api/v1/authn response differentiation. It sends two canary
// requests with emails in the target domain that should not exist; if the
// endpoint returns consistent error responses, it is worth checking real
// emails against the baseline.
func (c *Checker) DetectEnumeration(ctx context.Context, tenantURL string, domain string) *EnumSupport {
	support := &EnumSupport{TenantURL: tenantURL}

	canary1 := fmt.Sprintf("nonexistent-canary-alpha-x7q9@%s", domain)
	canary2 := fmt.Sprintf("nonexistent-canary-bravo-m3k8@%s", domain)

	probe1 := c.probeAuthn(ctx, tenantURL, canary1)
	if probe1.err != nil {
		support.Error = probe1.err
		return support
	}

	probe2 := c.probeAuthn(ctx, tenantURL, canary2)
	if probe2.err != nil {
		support.Error = probe2.err
		return support
	}

	if probe1.response.ErrorCode != probe2.response.ErrorCode {
		return support
	}

	if probe1.response.ErrorCode == "" {
		return support
	}

	support.Enumerable = true
	support.BaselineError = probe1.response.ErrorCode
	return support
}

// CheckAccount checks whether email exists on the Okta tenant by sending a
// deliberately invalid password to /api/v1/authn and comparing the response
// against the baseline error code from DetectEnumeration. Responses that
// differ from the baseline (different error code, MFA challenge, lockout
// status) indicate the account exists.
func (c *Checker) CheckAccount(ctx context.Context, tenantURL string, email string, baselineError string) *EnumResult {
	start := time.Now()
	result := &EnumResult{Email: email}
	defer func() { result.Duration = time.Since(start) }()

	probe := c.probeAuthn(ctx, tenantURL, email)
	if probe.err != nil {
		result.Error = probe.err
		return result
	}

	if probe.indicatesExistence() {
		result.Exists = true
		if probe.response.ErrorCode == errAccountLocked || probe.response.Status == "LOCKED_OUT" {
			result.Locked = true
		}
		return result
	}

	if probe.response.ErrorCode != baselineError {
		result.Exists = true
	}

	return result
}

func (c *Checker) probeAuthn(ctx context.Context, tenantURL, email string) authnProbeResult {
	body, err := json.Marshal(authnRequest{
		Username: email,
		Password: enumProbePassword,
	})
	if err != nil {
		return authnProbeResult{err: fmt.Errorf("marshaling request: %w", err)}
	}

	authnURL := strings.TrimRight(tenantURL, "/") + "/api/v1/authn"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authnURL, bytes.NewReader(body))
	if err != nil {
		return authnProbeResult{err: fmt.Errorf("creating request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return authnProbeResult{err: fmt.Errorf("request failed: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return authnProbeResult{err: fmt.Errorf("reading response: %w", err)}
	}

	var authnResp authnResponse
	if err := json.Unmarshal(raw, &authnResp); err != nil {
		return authnProbeResult{
			statusCode: resp.StatusCode,
			err:        fmt.Errorf("decoding response: %w", err),
		}
	}

	return authnProbeResult{
		statusCode: resp.StatusCode,
		response:   authnResp,
	}
}

// ---------------------------------------------------------------------------
// Federation cross-correlation
// ---------------------------------------------------------------------------

// ParseOktaTenantURL extracts the base Okta tenant URL from a federation
// redirect URL or bare IdP hostname. Returns "" if the input doesn't point
// to an Okta host.
func ParseOktaTenantURL(federationInput string) string {
	if federationInput == "" {
		return ""
	}

	if !strings.Contains(federationInput, "://") {
		if isOktaHost(federationInput) {
			return "https://" + federationInput
		}
		return ""
	}

	u, err := url.Parse(federationInput)
	if err != nil || u.Host == "" {
		return ""
	}

	if !isOktaHost(u.Host) {
		return ""
	}

	return u.Scheme + "://" + u.Host
}

func isOktaHost(host string) bool {
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".okta.com") ||
		strings.HasSuffix(host, ".oktapreview.com")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err == nil {
		dot := strings.IndexByte(reg, '.')
		if dot > 0 {
			return reg[:dot]
		}
	}

	dot := strings.IndexByte(domain, '.')
	if dot <= 0 {
		return ""
	}
	return domain[:dot]
}
