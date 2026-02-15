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

package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("ftp", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements FTP password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "ftp"
}

// Test attempts FTP password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials (230 response)
// - Success=false, Error=nil: Invalid credentials (530 response)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "ftp",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Connect with context-aware timeout
	conn, err := dialWithContext(ctx, "tcp", target, timeout)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Set overall deadline for FTP operations
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read welcome message (220)
	_, err = readResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Send USER command
	_, err = fmt.Fprintf(conn, "USER %s\r\n", username)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Read response (331 = need password, 230 = already logged in for anonymous)
	response, err := readResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Check if already logged in (anonymous with no password)
	if strings.HasPrefix(response, "230") {
		result.Success = true
		result.Duration = time.Since(start)
		return result
	}

	// Send PASS command
	_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Read response (230 = success, 530 = failure)
	response, err = readResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Check authentication result
	switch {
	case strings.HasPrefix(response, "230"):
		result.Success = true
	case strings.HasPrefix(response, "530"):
		// Auth failure - return nil error
		result.Error = nil
	default:
		// Unexpected response - connection error
		result.Error = fmt.Errorf("connection error: unexpected FTP response: %s", response)
	}

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

// readResponse reads a single FTP response line.
func readResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// classifyError classifies TCP dial errors.
// All dial errors are connection errors.
func classifyError(err error) error {
	return fmt.Errorf("connection error: %w", err)
}

// classifyAuthError classifies FTP authentication errors.
//
// Auth failure indicators (return nil):
// - "530" (Login incorrect / Authentication failed)
//
// All other errors are connection problems (return wrapped error).
func classifyAuthError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for FTP 530 response code (authentication failure)
	if strings.Contains(errStr, "530") {
		// This is an authentication failure, not a connection error
		return nil
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
