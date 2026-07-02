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
// Brutus API); this plugin is a thin adapter that maps an okta.Result to an
// enum.Result.
package okta

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	oktaenum "github.com/praetorian-inc/brutus/pkg/enum/okta"
)

func init() {
	enum.Register("okta", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks Okta tenant existence via the shared pkg/enum/okta checker
// (.well-known/openid-configuration probe).
type Plugin struct {
	// baseURLFmt overrides the Okta base URL pattern for testing.
	// Leave empty to use the default production endpoint.
	baseURLFmt string
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

	// Tenant found — the account is plausible but not individually confirmed.
	result.Exists = true
	result.Confidence = enum.ConfidenceLow

	return result
}
