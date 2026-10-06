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

package smb

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var smbAuthIndicators = []string{
	"STATUS_LOGON_FAILURE",
	"authentication failed",
	// go-smb2 surfaces STATUS_LOGON_FAILURE as this descriptive text rather
	// than the symbolic code, so match it explicitly.
	"the attempted logon is invalid",
	"bad username or authentication information",
}

func init() {
	brutus.Register("smb", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements SMB password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "smb"
}

// Test attempts SMB password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("smb", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "445")
	addr := net.JoinHostPort(host, port)

	// Unqualified names are local SAM logins. Leaving Domain empty makes
	// go-smb2 fill it with the challenge TargetName, which is the AD domain
	// on a member and locks that account across every host in the spray.
	domain, user, err := ntlmDomain(ctx, addr, username, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if domain == "" {
		result.Error = brutus.WrapConnError(fmt.Errorf("local auth: empty NTLM domain"))
		return result
	}

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Bound SMB negotiate/session-setup and IPC$ mount: DialWithProxy only
	// covers the TCP dial, so without this a server that stalls the handshake
	// hangs the worker.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: password,
			Domain:   domain,
		},
	}

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = session.Logoff() }()

	share, err := session.Mount("IPC$")
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = share.Umount() }()

	result.Success = true
	return result
}

// parseDomainUsername splits username into domain and username.
// An unqualified name or ".\user" has an empty domain: ntlmDomain fills that
// with the target computer name. DOMAIN\user is an explicit domain login.
func parseDomainUsername(username string) (domain, user string) {
	id := winlocal.Parse(username)
	if id.Local {
		return "", id.User
	}
	return id.Domain, id.User
}

var classifyError = brutus.NewClassifier(smbAuthIndicators)
