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

package pop3

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
	brutus.Register("pop3", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements POP3 password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "pop3"
}

// Test attempts POP3 password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials (+OK response)
// - Success=false, Error=nil: Invalid credentials (-ERR response)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "pop3",
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

	// Set overall deadline for POP3 operations
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read welcome message (+OK)
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

	// Read response (should be +OK)
	_, err = readResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
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

	// Read response (+OK = success, -ERR = failure)
	response, err := readResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Check authentication result
	switch {
	case strings.HasPrefix(response, "+OK"):
		result.Success = true
	case strings.HasPrefix(response, "-ERR"), strings.HasPrefix(response, "-err"):
		// Auth failure - return nil error
		result.Error = nil
	default:
		// Unexpected response - connection error
		result.Error = fmt.Errorf("connection error: unexpected POP3 response: %s", response)
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

// readResponse reads a single POP3 response line.
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

// classifyAuthError classifies POP3 authentication errors.
//
// Auth failure indicators (return nil):
// - "-ERR" (Authentication failed)
//
// All other errors are connection problems (return wrapped error).
func classifyAuthError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for POP3 -ERR response (authentication failure)
	if strings.Contains(errStr, "-ERR") || strings.Contains(errStr, "-err") {
		// This is an authentication failure, not a connection error
		return nil
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
