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

package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("ldap", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements LDAP password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "ldap"
}

// Test attempts LDAP password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
//
// The implementation tries binding with the username directly first,
// and if that fails with an auth error, attempts to construct a DN
// (Distinguished Name) and try again.
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "ldap",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target)

	// Build LDAP URL
	ldapURL := fmt.Sprintf("ldap://%s:%s", host, port)
	if port == "636" {
		ldapURL = fmt.Sprintf("ldaps://%s:%s", host, port)
	}

	// Connect to LDAP server with timeout
	// Use InsecureSkipVerify for LDAPS to allow self-signed certs
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := ldap.DialURL(ldapURL, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Set operation timeout
	conn.SetTimeout(timeout)

	// Try binding with simple username first
	err = conn.Bind(username, password)
	if err == nil {
		// Success with simple username
		result.Success = true
		result.Duration = time.Since(start)
		return result
	}

	// Check if it was an auth error
	if isAuthError(err) {
		// Try constructing DN and binding again
		// Try common DN patterns
		dnPatterns := []string{
			fmt.Sprintf("uid=%s,dc=example,dc=com", username),
			fmt.Sprintf("cn=%s,dc=example,dc=com", username),
			fmt.Sprintf("uid=%s,ou=users,dc=example,dc=com", username),
			fmt.Sprintf("cn=%s,ou=users,dc=example,dc=com", username),
		}

		for _, dn := range dnPatterns {
			err = conn.Bind(dn, password)
			if err == nil {
				// Success with DN
				result.Success = true
				result.Duration = time.Since(start)
				return result
			}

			// If not an auth error, break (it's a connection problem)
			if !isAuthError(err) {
				break
			}
		}
	}

	// Classify the error
	result.Error = classifyError(err)
	result.Duration = time.Since(start)
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 389.
func parseTarget(target string) (host, port string) {
	// Check if target contains port
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1]
	}
	// Default to port 389 if not specified
	return target, "389"
}

// isAuthError checks if the error is an authentication error.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// LDAP Result Code 49 is "Invalid Credentials"
	authFailures := []string{
		"invalid credentials",
		"result code 49",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}

	return false
}

// classifyError classifies LDAP errors.
//
// Auth failure indicators (return nil):
// - "Invalid Credentials"
// - LDAP Result Code 49
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's an authentication failure
	if isAuthError(err) {
		// This is an authentication failure, not a connection error
		return nil
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
