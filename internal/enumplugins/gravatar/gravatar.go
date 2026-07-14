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

// Package gravatar registers the Gravatar account-existence oracle. The
// detection logic lives in pkg/enum/gravatar (the single source of truth, also
// consumable via the Brutus API); this plugin is a thin adapter that maps a
// gravatar.Result to an enum.Result.
package gravatar

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	gravatarenum "github.com/praetorian-inc/brutus/pkg/enum/gravatar"
)

func init() {
	enum.Register("gravatar", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks Gravatar account existence via the shared pkg/enum/gravatar
// checker (avatar endpoint with d=404). Proxy support is preserved: the checker
// honors the per-run enum HTTP client carried on ctx.
type Plugin struct{}

func (p *Plugin) Name() string { return "gravatar" }

// Check tests if an email has a registered Gravatar. Both outcomes are
// definitive (200 -> exists, 404 -> not registered), so a clean check reports
// ConfidenceHigh in either case; a service error leaves Exists=false and
// propagates the error.
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	checker, err := gravatarenum.NewChecker("", "", timeout)
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

	result.Confidence = enum.ConfidenceHigh
	return result
}
