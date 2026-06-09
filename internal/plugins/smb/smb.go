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
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var smbAuthIndicators = []string{
	"STATUS_LOGON_FAILURE",
	"authentication failed",
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

	// Parse target to extract host and port
	host, port := brutus.ParseTarget(target, "445")

	// Connect with context timeout (proxy-aware)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Parse domain and username
	domain, user := parseDomainUsername(username)

	// Perform SMB handshake and authentication
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

	// Test authentication by connecting to IPC$ share
	share, err := session.Mount("IPC$")
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = share.Umount() }()

	// Success - authentication worked
	result.Success = true
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 445 (SMB).
// Supports IPv6 addresses with brackets: [::1]:445
// parseDomainUsername splits username into domain and username.
// Supports formats: DOMAIN\username or just username.
// Returns empty string for domain if not specified.
func parseDomainUsername(username string) (domain, user string) {
	// Check for DOMAIN\username format
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		return parts[0], parts[1]
	}
	// No domain specified
	return "", username
}

var classifyError = brutus.NewClassifier(smbAuthIndicators)
