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

package telnet

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("telnet", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Telnet password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "telnet"
}

// Test attempts Telnet password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "telnet",
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

	// Set overall timeout
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read until login prompt (capture banner)
	banner, err := waitForPrompt(reader, isLoginPrompt, timeout)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	result.Banner = banner

	// Send username
	if _, writeErr := fmt.Fprintf(conn, "%s\n", username); writeErr != nil {
		result.Error = fmt.Errorf("connection error: %w", writeErr)
		result.Duration = time.Since(start)
		return result
	}

	// Read until password prompt
	_, err = waitForPrompt(reader, isPasswordPrompt, timeout)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Send password
	if _, writeErr := fmt.Fprintf(conn, "%s\n", password); writeErr != nil {
		result.Error = fmt.Errorf("connection error: %w", writeErr)
		result.Duration = time.Since(start)
		return result
	}

	// Read response and check for success/failure
	response, err := readResponse(reader, timeout)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Classify response
	result.Error = classifyTelnetResponse(response)
	if result.Error == nil {
		// Either auth failure or success
		if isSuccessIndicator(response) {
			result.Success = true
		}
		// If not success and Error==nil, it's auth failure
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

// classifyError classifies TCP dial errors.
// All dial errors are connection errors.
func classifyError(err error) error {
	return fmt.Errorf("connection error: %w", err)
}

// waitForPrompt reads from the connection until a prompt is detected.
func waitForPrompt(reader *bufio.Reader, isPrompt func(string) bool, timeout time.Duration) (string, error) {
	buffer := make([]byte, 0, 4096)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return string(buffer), fmt.Errorf("unexpected EOF")
			}
			return string(buffer), err
		}

		buffer = append(buffer, b)
		line := string(buffer)

		if isPrompt(line) {
			return line, nil
		}

		// Prevent buffer overflow
		if len(buffer) > 4096 {
			buffer = buffer[1:]
		}
	}

	return string(buffer), fmt.Errorf("timeout waiting for prompt")
}

// readResponse reads the response after sending password.
func readResponse(reader *bufio.Reader, timeout time.Duration) (string, error) {
	buffer := make([]byte, 0, 4096)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		_, _ = reader.ReadByte()
		b, err := reader.ReadByte()
		if err != nil {
			// Check what we have so far
			if len(buffer) > 0 {
				return string(buffer), nil
			}
			if err == io.EOF {
				return "", fmt.Errorf("unexpected EOF")
			}
			return "", err
		}

		buffer = append(buffer, b)

		// Check for success or failure indicators
		line := string(buffer)
		if isSuccessIndicator(line) || isFailureIndicator(line) {
			// Read a bit more to get full response
			time.Sleep(100 * time.Millisecond)
			for reader.Buffered() > 0 {
				if b, err := reader.ReadByte(); err == nil {
					buffer = append(buffer, b)
				}
			}
			return string(buffer), nil
		}

		// Prevent buffer overflow
		if len(buffer) > 4096 {
			break
		}
	}

	return string(buffer), nil
}

// classifyTelnetResponse classifies Telnet authentication responses.
//
// Auth failure indicators (return nil):
// - "login incorrect"
// - "authentication failed"
// - "access denied"
// - "invalid credentials"
//
// Success indicators (return nil):
// - Shell prompts ($ or #)
//
// All other errors are connection problems (return wrapped error).
func classifyTelnetResponse(response string) error {
	if response == "" {
		return fmt.Errorf("connection error: empty response")
	}

	respLower := strings.ToLower(response)

	// Check for connection errors first
	if strings.Contains(respLower, "connection closed") {
		return fmt.Errorf("connection error: connection closed")
	}

	// Check for auth failures (return nil)
	if isFailureIndicator(response) {
		return nil
	}

	// Check for success (return nil)
	if isSuccessIndicator(response) {
		return nil
	}

	// Ambiguous response treated as connection error
	return fmt.Errorf("connection error: unexpected response")
}

// isLoginPrompt checks if the text contains a login prompt.
func isLoginPrompt(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "login:") ||
		strings.Contains(lower, "username:") ||
		strings.Contains(lower, "user:")
}

// isPasswordPrompt checks if the text contains a password prompt.
func isPasswordPrompt(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "password:") ||
		strings.Contains(lower, "pass:")
}

// isSuccessIndicator checks if the response indicates successful authentication.
// Success is indicated by shell prompts ($ or #).
func isSuccessIndicator(response string) bool {
	// Check for $ or # at the end of response (shell prompt)
	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return false
	}

	lastChar := trimmed[len(trimmed)-1]
	return lastChar == '$' || lastChar == '#'
}

// isFailureIndicator checks if the response indicates authentication failure.
func isFailureIndicator(response string) bool {
	lower := strings.ToLower(response)

	failureIndicators := []string{
		"incorrect",
		"failed",
		"denied",
		"invalid",
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	return false
}
