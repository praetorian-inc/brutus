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
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ldapAuthIndicators identifies LDAP authentication failures.
// LDAP Result Code 49 is "Invalid Credentials".
var ldapAuthIndicators = []string{
	"invalid credentials",
	"result code 49",
	"result code 32", // noSuchObject - invalid DN
	"result code 50", // insufficientAccessRights
}

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

	result := brutus.NewResult("ldap", target, username, password)

	// Parse target to extract host and port
	host, port := brutus.ParseTarget(target, "389")

	// Build LDAP URL
	ldapURL := fmt.Sprintf("ldap://%s:%s", host, port)
	if port == "636" {
		ldapURL = fmt.Sprintf("ldaps://%s:%s", host, port)
	}

	// Connect to LDAP server with timeout
	// Read TLS mode from context
	tlsMode := brutus.TLSModeFromContext(ctx)

	// Configure TLS based on mode
	// Note: For LDAP, even "disable" needs TLS config for LDAPS (port 636)
	dialer := &net.Dialer{Timeout: timeout}
	var tlsConfig *tls.Config
	switch tlsMode {
	case "verify":
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
		}
	default: // "skip-verify" or "disable" - both allow self-signed for LDAPS
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
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

	// If simple bind failed with an auth error, no further fallback attempts.
	// The previous dc=example,dc=com DN patterns were dead code that never
	// matched real LDAP directories.

	// Classify the error
	result.Error = classifyError(err)
	result.Duration = time.Since(start)
	return result
}

var classifyError = brutus.NewClassifier(ldapAuthIndicators)
