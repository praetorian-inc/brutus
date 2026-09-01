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

package rdp

import (
	"context"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// testGordp validates credentials through the native library.
//
// It preserves the three-way outcome the plugin contract is built on, which the
// caller distinguishes by looking at Success and Error together:
//
//	Success=true,  Error=nil   the credentials are valid
//	Success=false, Error=nil   the credentials were rejected
//	Success=false, Error!=nil  the host could not be reached or spoke badly
//
// Collapsing the last two would be the damaging mistake: a network failure
// reported as a rejected password makes a scan quietly conclude that a valid
// credential does not work.
func (p *Plugin) testGordp(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {

	start := time.Now()
	result := brutus.NewResult("rdp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	// Split DOMAIN\username, matching the SMB plugin so one credential list
	// works across both.
	domain, user := parseDomainUsername(username)

	dial, err := dialGordp(ctx, addr, pluginCfg.ProxyURL, rdpConfig{
		Server:   addr,
		Username: user,
		Password: password,
		Domain:   domain,
	}, detectWidth, detectHeight, timeout)

	if err != nil {
		// classifyError matches the message against rdpAuthIndicators, which is
		// what turns "authentication failed: ..." into a credential rejection
		// and anything else into a transport error.
		result.Error = classifyError(err)
	} else {
		// Reaching an active session means the server accepted the credentials.
		result.Success = true
		result.Banner = dial.banner

		// Close before running the pre-auth checks below. Windows Server allows
		// only two concurrent sessions, and holding this one open while opening
		// two more would exhaust the host and make its own checks fail.
		_ = dial.session.Close(ctx)
	}

	// The sticky keys and utilman checks are pre-authentication and run on their
	// own connections, so they happen regardless of the credential outcome.
	if !pluginCfg.NoStickyKeys {
		if sticky := p.RunStickyKeysCheck(ctx, target, pluginCfg.ProxyURL, timeout, timeout,
			pluginCfg.NoVision, CarefulBudget, false); sticky != nil {
			result.Banner = formatStickyKeysBanner(result.Banner, sticky)
		}
		if utilman := p.RunUtilmanCheck(ctx, target, pluginCfg.ProxyURL, timeout, timeout,
			pluginCfg.NoVision, CarefulBudget, false); utilman != nil {
			result.Banner = formatUtilmanBanner(result.Banner, utilman)
		}
	}

	return result
}
