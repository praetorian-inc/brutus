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

package ssh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// sshAuthIndicators lists error strings that indicate authentication failure
// (wrong credentials) rather than connection issues.
var sshAuthIndicators = []string{
	"unable to authenticate",
	"permission denied",
	"no supported methods remain",
	"keyboard-interactive",            // Some SSH servers use this for password auth failures
	"publickey authentication failed", // Key-based auth rejection
}

func init() {
	brutus.Register("ssh", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements SSH password and key-based authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "ssh"
}

// Test attempts SSH password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("ssh", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Create SSH client config
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	// Connect with context-aware timeout
	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}
	defer func() { _ = sshConn.Close() }()

	// Capture SSH server version banner
	result.Banner = string(sshConn.ServerVersion())

	// Discard channels and requests (cleanup)
	go ssh.DiscardRequests(reqs)
	go func() {
		for range chans {
		}
	}()

	// Success
	result.Success = true
	return result
}

// TestKey attempts SSH key-based authentication using the provided private key.
//
// Returns Result with:
// - Success=true, Error=nil: Valid key
// - Success=false, Error=nil: Invalid key (auth failure)
// - Success=false, Error!=nil: Connection/network/key parsing error
func (p *Plugin) TestKey(ctx context.Context, target, username string, key []byte,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("ssh", target, username, "")
	defer func() { result.Duration = time.Since(start) }()
	result.Key = key

	// Validate key is provided
	if len(key) == 0 {
		result.Error = fmt.Errorf("connection error: empty private key")
		return result
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// Check if key is passphrase-protected
		if strings.Contains(err.Error(), "encrypted") || strings.Contains(err.Error(), "passphrase") {
			result.Error = fmt.Errorf("connection error: passphrase-protected keys not supported")
		} else {
			result.Error = fmt.Errorf("connection error: failed to parse private key: %w", err)
		}
		return result
	}

	// Create SSH client config with public key auth
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	// Connect with context-aware timeout
	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}
	defer func() { _ = sshConn.Close() }()

	// Capture SSH server version banner
	result.Banner = string(sshConn.ServerVersion())

	// Discard channels and requests (cleanup)
	go ssh.DiscardRequests(reqs)
	go func() {
		for range chans {
		}
	}()

	// Success
	result.Success = true
	return result
}

// classifyAuthError classifies SSH authentication errors.
//
// Auth failure indicators (return nil):
// - "unable to authenticate"
// - "permission denied"
// - "no supported methods remain"
//
// All other errors are connection problems (return wrapped error).
func classifyAuthError(err error) error {
	return brutus.ClassifyAuthError(err, sshAuthIndicators)
}
