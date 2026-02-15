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
	"strings"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "imap",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	// Create context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create options for dialing with context
	options := &imapclient.Options{
		// Use the context from the cancel function
	}

	// Dial IMAP server
	client, err := imapclient.DialInsecure(addr, options)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer client.Close()

	// Check if context was canceled during dial
	if dialCtx.Err() != nil {
		result.Error = classifyError(dialCtx.Err())
		result.Duration = time.Since(start)
		return result
	}

	// Create context with timeout for login
	loginCtx, loginCancel := context.WithTimeout(ctx, timeout)
	defer loginCancel()

	// Attempt LOGIN authentication
	loginCmd := client.Login(username, password)
	err = loginCmd.Wait()

	// Check if context was canceled during login
	if loginCtx.Err() != nil {
		result.Error = classifyError(loginCtx.Err())
		result.Duration = time.Since(start)
		return result
	}

	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 143.
func parseTarget(target string) (host, port string) {
	// Check if target contains port
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1]
	}
	// Default to port 143 if not specified
	return target, "143"
}

// classifyError classifies IMAP connection errors.
// All connection errors are wrapped as connection errors.
func classifyError(err error) error {
	return fmt.Errorf("connection error: %w", err)
}

// classifyAuthError classifies IMAP authentication errors.
//
// Auth failure indicators (return nil):
// - "authentication failed"
// - "NO" response (IMAP authentication failure)
//
// All other errors are connection problems (return wrapped error).
func classifyAuthError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"authentication failed",
		"authenticate",
		"invalid credentials",
		"login failed",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			// This is an authentication failure
			return nil
		}
	}

	// Check for IMAP NO response which indicates auth failure
	if strings.Contains(errStr, "no ") {
		return nil
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
