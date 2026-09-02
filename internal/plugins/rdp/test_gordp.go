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
	"fmt"
	"net"
	"time"

	gsession "github.com/UNC1739/gordp/pkg/session"

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

	switch {
	case err != nil:
		// classifyError matches the message against rdpAuthIndicators, which is
		// what turns "authentication failed: ..." into a credential rejection
		// and anything else into a transport error.
		result.Error = classifyError(err)

	case dial.credsspProved:
		// CredSSP completed, which is itself proof: the server validated the
		// credentials before the connection was allowed to proceed.
		result.Success = true
		result.Banner = dial.banner
		_ = dial.session.Close(ctx)

	default:
		// CredSSP was not used, so the connection completing proves nothing: the
		// server accepts it either way and reports the logon outcome afterwards.
		// Waiting for that verdict is the difference between testing a credential
		// and merely reaching a host.
		var confirmErr error
		result.Success, result.Banner, confirmErr = confirmNonNLALogon(ctx, dial)
		result.Error = confirmErr
		_ = dial.session.Close(ctx)
	}

	return result
}

// nonNLALogonWait bounds how long to wait for a server's logon verdict.
//
// Real Windows reports a successful logon within about two seconds, so this is
// generous. It stays bounded because a scan cannot afford to wait on every host
// that simply says nothing, which is what Windows does for a wrong password.
const nonNLALogonWait = 8 * time.Second

// confirmNonNLALogon waits for the server to report whether the logon happened.
//
// It returns the credential verdict, a banner describing what was seen, and an
// error when the question could not be answered at all.
//
// That third outcome is the important one. Some servers — xrdp among them —
// complete the connection without CredSSP and then never report a logon result,
// because their own login dialog handles authentication. Against those, no
// password can be confirmed or refuted. Reporting that as "rejected" would be a
// quiet lie about a host that was never actually tested, so it is reported as an
// error instead: the plugin contract already distinguishes "this password is
// wrong" from "this host could not be tested", and this is the latter.
//
// A wrong password against Windows does not reach here: CredSSP fails first and
// is classified as a rejection.
func confirmNonNLALogon(ctx context.Context, dial *gordpDialResult) (success bool, banner string, err error) {
	outcome, detail, waitErr := dial.session.WaitForLogon(ctx, nonNLALogonWait)
	if waitErr != nil {
		return false, dial.banner, fmt.Errorf("connection error: waiting for the logon result: %w", waitErr)
	}

	switch outcome {
	case gsession.LogonSucceeded:
		return true, fmt.Sprintf("%s; %s (CredSSP not used, so the server's identity was not proven)",
			dial.banner, detail), nil

	case gsession.LogonFailed:
		return false, fmt.Sprintf("%s; logon refused: %s", dial.banner, detail), nil

	default:
		return false, fmt.Sprintf("%s; %s", dial.banner, detail),
			fmt.Errorf("connection error: the server completed the connection without CredSSP " +
				"and reported no logon result, so the credentials could not be validated")
	}
}
