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

// Package microsoft365 registers the Microsoft 365 account-existence oracle.
// The detection logic lives in pkg/enum/microsoft365 (the single source of
// truth, also consumable via the Brutus API); this plugin is a thin adapter
// that maps a microsoft365.Result to an enum.Result.
package microsoft365

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	ms365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

func init() {
	enum.Register("microsoft365", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks Microsoft 365 account existence via the shared
// pkg/enum/microsoft365 checker (GetCredentialType API). Proxy support is
// preserved: the checker honors the per-run enum HTTP client carried on ctx.
type Plugin struct{}

func (p *Plugin) Name() string { return "microsoft365" }

func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	checker, err := ms365.NewChecker("", "", timeout)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	res := checker.CheckAccount(ctx, email)

	result.Exists = res.Exists
	result.Error = res.Error
	result.Duration = time.Since(start)

	if res.Error != nil {
		return result
	}

	switch res.IfExistsResult {
	case ms365.IfExistsResultExists, ms365.IfExistsResultDifferentTenant, ms365.IfExistsResultDomainHint:
		result.Confidence = enum.ConfidenceHigh
	case ms365.IfExistsResultNotExists:
		result.Confidence = enum.ConfidenceHigh
	default:
		result.Confidence = enum.ConfidenceLow
	}

	return result
}
