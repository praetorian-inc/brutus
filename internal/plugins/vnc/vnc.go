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

package vnc

import (
	"context"
	"time"

	"github.com/mitchellh/go-vnc"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// vncAuthIndicators defines authentication failure strings returned by VNC servers
var vncAuthIndicators = []string{
	"authentication failed",
	"invalid password",
	"auth failed",
}

func init() {
	brutus.Register("vnc", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements VNC password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "vnc"
}

// Test attempts VNC password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
//
// Note: VNC uses password-only authentication. The username parameter is ignored.
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("vnc", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Connect to VNC server (proxy-aware)
	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Create VNC client configuration
	cfg := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{Password: password},
		},
	}

	// Attempt VNC handshake and authentication
	_, err = vnc.Client(conn, cfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(vncAuthIndicators)
