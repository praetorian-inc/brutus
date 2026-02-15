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
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "smb",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target)

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Connect with context timeout
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

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
		result.Duration = time.Since(start)
		return result
	}
	defer func() { _ = session.Logoff() }()

	// Test authentication by connecting to IPC$ share
	share, err := session.Mount("IPC$")
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer func() { _ = share.Umount() }()

	// Success - authentication worked
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 445 (SMB).
func parseTarget(target string) (host, port string) {
	// Check if target contains port
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1]
	}
	// Default to port 445 if not specified
	return target, "445"
}

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

// classifyError classifies SMB errors.
//
// Auth failure indicators (return nil):
// - "STATUS_LOGON_FAILURE"
// - "authentication failed"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authentication failure indicators
	authFailures := []string{
		"STATUS_LOGON_FAILURE",
		"authentication failed",
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
