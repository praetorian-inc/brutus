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
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ftpAuthIndicators lists error strings that indicate authentication failure
// (wrong credentials) rather than connection issues.
var ftpAuthIndicators = []string{
	"530", // FTP response code for authentication failure
}

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("ftp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Connect with context-aware timeout
	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	// Set overall deadline for FTP operations
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read welcome message (220), consuming any multi-line banner
	_, err = readFTPResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}

	// Send USER command
	_, err = fmt.Fprintf(conn, "USER %s\r\n", username)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}

	// Read response (331 = need password, 230 = already logged in for anonymous)
	response, err := readFTPResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}

	// Check if already logged in (anonymous with no password)
	if strings.HasPrefix(response, "230") {
		result.Success = true
		return result
	}

	// Only proceed to PASS if the server accepted USER and is waiting for a password.
	// 331 = "User name okay, need password"
	if !strings.HasPrefix(response, "331") {
		if strings.HasPrefix(response, "530") {
			// User rejected (e.g. user not allowed)
			result.Error = nil
			return result
		}
		result.Error = fmt.Errorf("connection error: unexpected FTP response to USER: %s", response)
		return result
	}

	// Send PASS command
	_, err = fmt.Fprintf(conn, "PASS %s\r\n", password)
	if err != nil {
		result.Error = classifyAuthError(err)
		return result
	}

	// Read response (230 = success, 530 = failure)
	response, err = readFTPResponse(reader)
	if err != nil {
		result.Error = classifyAuthError(err)
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

	return result
}

// readFTPResponse reads a complete FTP response, consuming multi-line replies.
// Multi-line FTP responses use "NNN-" for continuation lines and "NNN " (with
// a space) for the final line (RFC 959 Section 4.2). Returns the final line.
func readFTPResponse(reader *bufio.Reader) (string, error) {
	for {
		line, err := brutus.ReadLine(reader)
		if err != nil {
			return "", err
		}
		// Final line: 3-digit code followed by space (or end of string).
		// Continuation line: 3-digit code followed by hyphen.
		if len(line) == 3 || (len(line) > 3 && line[3] != '-') {
			return line, nil
		}
	}
}

// classifyAuthError classifies FTP authentication errors.
// Delegates to the shared brutus.ClassifyAuthError helper.
func classifyAuthError(err error) error {
	return brutus.ClassifyAuthError(err, ftpAuthIndicators)
}
