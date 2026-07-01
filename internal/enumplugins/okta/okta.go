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

// Package okta registers the Okta org-aware probe oracle. The detection logic
// lives in pkg/enum/okta (the single source of truth, also consumable via the
// Brutus API); this plugin is a thin adapter that maps okta results to
// enum.Result.
//
// When a tenant is found, the plugin probes /api/v1/authn for username
// enumeration. If the tenant is misconfigured and leaks existence, the per-
// email check upgrades from low to high confidence.
package okta

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	oktaenum "github.com/praetorian-inc/brutus/pkg/enum/okta"
)

func init() {
	enum.Register("okta", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks Okta tenant existence and, when the tenant is misconfigured,
// performs per-email account enumeration via /api/v1/authn.
type Plugin struct {
	baseURLFmt string

	enumOnce    sync.Once
	enumSupport *oktaenum.EnumSupport
	tenantURL   string
}

func (p *Plugin) Name() string { return "okta" }

func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	checker := oktaenum.NewChecker(p.baseURLFmt, timeout)
	res := checker.CheckTenant(ctx, email)

	result.Error = res.Error
	result.Duration = time.Since(start)

	if res.Error != nil {
		return result
	}

	if !res.HasTenant {
		result.Confidence = enum.ConfidenceLow
		return result
	}

	result.Exists = true
	result.Confidence = enum.ConfidenceLow

	domain := domainFromEmail(email)
	if domain == "" {
		return result
	}

	p.enumOnce.Do(func() {
		p.tenantURL = res.TenantURL
		p.enumSupport = checker.DetectEnumeration(ctx, res.TenantURL, domain)
	})

	if p.enumSupport == nil || p.enumSupport.Error != nil || !p.enumSupport.Enumerable {
		return result
	}

	enumRes := checker.CheckAccount(ctx, p.tenantURL, email, p.enumSupport.BaselineError)
	if enumRes.Error != nil {
		return result
	}

	if enumRes.Exists {
		result.Exists = true
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Exists = false
		result.Confidence = enum.ConfidenceHigh
	}

	result.Duration = time.Since(start)
	return result
}

func domainFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
