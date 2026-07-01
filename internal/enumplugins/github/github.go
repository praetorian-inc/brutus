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

// Package github registers the GitHub account-existence oracle. The detection
// logic lives in pkg/enum/github (the single source of truth, also used by the
// "enum github" command); this plugin is a thin adapter that maps a
// github.Result to an enum.Result.
//
// Only the unauthenticated existence path is used here: the github.com/join
// email_validity_checks endpoint reports whether an email is already tied to a
// GitHub account (HTTP 422 = in use, HTTP 200 = available). No token is required,
// so the oracle stays in the unauthenticated enumeration set alongside google and
// microsoft365. The token-gated username-reveal path is intentionally not exposed
// through the oracle interface.
package github

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

func init() {
	enum.Register("github", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks GitHub account existence via the shared pkg/enum/github
// enumerator (unauthenticated email_validity_checks endpoint).
type Plugin struct{}

func (p *Plugin) Name() string { return "github" }

// Check tests if an email account exists on GitHub, building a fresh
// (unauthenticated, honoring --proxy from context) enumerator per call and
// delegating to the existence path. token is empty (existence-only) and
// rotatingProxy is false: the oracle path makes a single check per email, so the
// rotating-proxy backoff tuning that benefits bulk enumeration does not apply.
//
// The existence endpoint is definitive — HTTP 422 (in use) and HTTP 200
// (available) are both unambiguous — so confidence is high whenever the check
// completes without error.
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	enumerator, err := githubenum.NewEnumerator(enum.ProxyURLFromContext(ctx), timeout, "", false)
	if err != nil {
		result.Confidence = enum.ConfidenceMedium
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	// Single-email existence check via the batch API (threads=1, no rate
	// limit/jitter): the oracle worker pool already paces calls. Enumerate always
	// returns one Result for one input email.
	res := enumerator.Enumerate(ctx, []string{email}, 1, 0, 0)[0]
	if res.Error != nil {
		result.Confidence = enum.ConfidenceMedium
		result.Error = res.Error
		result.Duration = time.Since(start)
		return result
	}

	result.Exists = res.Exists
	result.Confidence = enum.ConfidenceHigh
	result.Duration = time.Since(start)
	return result
}
