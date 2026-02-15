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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mitchellh/go-vnc"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "vnc",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Connect to VNC server
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

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
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// classifyError classifies VNC errors.
//
// Auth failure indicators (return nil):
// - "authentication failed"
// - "invalid password"
// - "auth failed"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"authentication failed",
		"invalid password",
		"auth failed",
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
