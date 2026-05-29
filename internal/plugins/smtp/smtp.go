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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// smtpAuthIndicators contains strings that indicate SMTP authentication failures.
// Used by ClassifyAuthError to distinguish auth failures from connection errors.
var smtpAuthIndicators = []string{
	"535",                                // SMTP auth failure code
	"authentication failed",              // Common error message
	"Authentication credentials invalid", // Alternative wording
	"invalid username or password",       // Alternative wording
}

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("smtp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Connect with timeout (proxy-aware)
	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Set deadline for the entire operation
	deadline := time.Now().Add(timeout)
	if deadlineErr := conn.SetDeadline(deadline); deadlineErr != nil {
		result.Error = brutus.WrapConnError(deadlineErr)
		return result
	}

	// Create SMTP client
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		result.Error = fmt.Errorf("connection error: invalid target format: %w", err)
		return result
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = client.Close() }()

	// Try STARTTLS if available
	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode
	if tlsMode != "disable" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			var tlsConfig *tls.Config
			switch tlsMode {
			case "verify":
				tlsConfig = &tls.Config{InsecureSkipVerify: false, ServerName: host}
			default: // "skip-verify"
				tlsConfig = &tls.Config{InsecureSkipVerify: true, ServerName: host}
			}
			if tlsErr := client.StartTLS(tlsConfig); tlsErr != nil {
				// STARTTLS failure is a connection error, not auth failure
				result.Error = fmt.Errorf("connection error: STARTTLS failed: %w", tlsErr)
				return result
			}
		}
	}

	// Create auth mechanism (try PLAIN first, which is most common)
	auth := smtp.PlainAuth("", username, password, host)

	// Attempt authentication
	err = client.Auth(auth)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(smtpAuthIndicators)
