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

package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("smtp", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements SMTP password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "smtp"
}

// Test attempts SMTP password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials (235 response)
// - Success=false, Error=nil: Invalid credentials (535 response)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "smtp",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Connect with timeout
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Set deadline for the entire operation
	deadline := time.Now().Add(timeout)
	if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
		result.Error = fmt.Errorf("connection error: %w", deadlineErr)
		result.Duration = time.Since(start)
		return result
	}

	// Create SMTP client
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		result.Error = fmt.Errorf("connection error: invalid target format: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer client.Close()

	// Try STARTTLS if available
	// Use InsecureSkipVerify to allow self-signed certs
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: host}
		if tlsErr := client.StartTLS(tlsConfig); tlsErr != nil {
			// STARTTLS failure is a connection error, not auth failure
			result.Error = fmt.Errorf("connection error: STARTTLS failed: %w", tlsErr)
			result.Duration = time.Since(start)
			return result
		}
	}

	// Create auth mechanism (try PLAIN first, which is most common)
	auth := smtp.PlainAuth("", username, password, host)

	// Attempt authentication
	err = client.Auth(auth)
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

// classifyError classifies SMTP errors.
//
// Auth failure indicators (return nil):
// - "535" response code (authentication failed)
// - "authentication failed"
// - "Authentication credentials invalid"
// - "invalid username or password"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authentication failure indicators
	authFailures := []string{
		"535",                                // SMTP auth failure code
		"authentication failed",              // Common error message
		"Authentication credentials invalid", // Alternative wording
		"invalid username or password",       // Alternative wording
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
