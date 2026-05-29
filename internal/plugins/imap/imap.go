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

package imap

import (
	"context"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var imapAuthIndicators = []string{
	"authentication failed",
	"authenticate",
	"invalid credentials",
	"login failed",
}

func init() {
	brutus.Register("imap", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements IMAP password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "imap"
}

// Test attempts IMAP password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("imap", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Parse target to extract host and port
	host, port := brutus.ParseTarget(target, "143")
	addr := fmt.Sprintf("%s:%s", host, port)

	// Create context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create options
	options := &imapclient.Options{}

	// Dial IMAP server (proxy-aware)
	var client *imapclient.Client
	if pluginCfg.ProxyURL != "" {
		conn, dialErr := brutus.DialWithProxy(dialCtx, "tcp", addr, timeout, pluginCfg.ProxyURL)
		if dialErr != nil {
			result.Error = classifyError(dialErr)
			return result
		}
		client = imapclient.New(conn, options)
	} else {
		var dialErr error
		client, dialErr = imapclient.DialInsecure(addr, options)
		if dialErr != nil {
			result.Error = classifyError(dialErr)
			return result
		}
	}
	defer func() { _ = client.Close() }()

	// Check if context was canceled during dial
	if dialCtx.Err() != nil {
		result.Error = classifyError(dialCtx.Err())
		return result
	}

	// Create context with timeout for login
	loginCtx, loginCancel := context.WithTimeout(ctx, timeout)
	defer loginCancel()

	// Attempt LOGIN authentication
	loginCmd := client.Login(username, password)
	err := loginCmd.Wait()

	// Check if context was canceled during login
	if loginCtx.Err() != nil {
		result.Error = classifyError(loginCtx.Err())
		return result
	}

	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(imapAuthIndicators)
