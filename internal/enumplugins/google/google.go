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

// Package google registers the Google Workspace account-existence oracle. The
// detection logic lives in pkg/enum/google (the single source of truth, also
// used by the "enum google" command); this plugin is a thin adapter that maps a
// google.Result to an enum.Result.
package google

import (
	"context"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	googleenum "github.com/praetorian-inc/brutus/pkg/enum/google"
)

func init() {
	enum.Register("google", func() enum.Plugin {
		return &Plugin{}
	})
}

// Plugin checks Google Workspace account existence via the shared
// pkg/enum/google enumerator (AccountChooser SSO + GXLU).
type Plugin struct{}

func (p *Plugin) Name() string { return "google" }

// Check tests if an email account exists on Google Workspace, building a fresh
// (unauthenticated, honoring --proxy from context) enumerator per call and delegating to
// google.CheckAccount. Confidence is high when the account is confirmed,
// medium otherwise — preserving the previous plugin behavior.
func (p *Plugin) Check(ctx context.Context, email string, timeout time.Duration) *enum.Result {
	start := time.Now()
	result := &enum.Result{
		Service: p.Name(),
		Email:   email,
	}

	enumerator, err := googleenum.NewEnumerator(enum.ProxyURLFromContext(ctx), timeout)
	if err != nil {
		result.Confidence = enum.ConfidenceMedium
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	res := enumerator.CheckAccount(ctx, email)
	result.Exists = res.Exists
	if res.Exists {
		result.Confidence = enum.ConfidenceHigh
	} else {
		result.Confidence = enum.ConfidenceMedium
	}
	result.Duration = time.Since(start)
	return result
}
