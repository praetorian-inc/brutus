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
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "ssh",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

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
	conn, err := dialWithContext(ctx, "tcp", target, timeout)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer sshConn.Close()

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
	result.Duration = time.Since(start)
	return result
}

// TestKey attempts SSH key-based authentication using the provided private key.
//
// Returns Result with:
// - Success=true, Error=nil: Valid key
// - Success=false, Error=nil: Invalid key (auth failure)
// - Success=false, Error!=nil: Connection/network/key parsing error
func (p *Plugin) TestKey(ctx context.Context, target, username string, key []byte,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "ssh",
		Target:   target,
		Username: username,
		Key:      key,
		Success:  false,
	}

	// Validate key is provided
	if len(key) == 0 {
		result.Error = fmt.Errorf("connection error: empty private key")
		result.Duration = time.Since(start)
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
		result.Duration = time.Since(start)
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
	conn, err := dialWithContext(ctx, "tcp", target, timeout)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer sshConn.Close()

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
	result.Duration = time.Since(start)
	return result
}

// dialWithContext performs context-aware TCP dialing.
func dialWithContext(ctx context.Context, network, address string,
	timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	return dialer.DialContext(ctx, network, address)
}

// classifyError classifies TCP dial errors.
// All dial errors are connection errors.
func classifyError(err error) error {
	return fmt.Errorf("connection error: %w", err)
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
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"unable to authenticate",
		"permission denied",
		"no supported methods remain",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			// This is an authentication failure, not a connection error
			return nil
		}
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
