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
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// telnetAuthIndicators lists response strings that indicate authentication failure
// (wrong credentials) rather than connection issues.
var telnetAuthIndicators = []string{
	"incorrect",
	"failed",
	"denied",
	"invalid",
}

// ansiCSIPattern matches ANSI CSI escape sequences (e.g. "\x1b[32m", "\x1b[0m",
// "\x1b[6n") so they can be stripped without disturbing surrounding text.
var ansiCSIPattern = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// responseSettleWindow bounds how long readResponse waits for additional bytes
// after the stream has last produced data. Reading continues until the stream is
// idle for this window (or EOF/overall deadline), so a prompt or failure message
// arriving after a banner is still captured rather than truncated.
const responseSettleWindow = 250 * time.Millisecond

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("telnet", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	conn, err := brutus.DialWithProxy(ctx, "tcp", target, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	banner, err := waitForPrompt(reader, isLoginPrompt, timeout)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	result.Banner = banner

	// Telnet requires CR+LF line endings.
	if _, writeErr := fmt.Fprintf(conn, "%s\r\n", username); writeErr != nil {
		result.Error = brutus.WrapConnError(writeErr)
		return result
	}

	_, err = waitForPrompt(reader, isPasswordPrompt, timeout)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	if _, writeErr := fmt.Fprintf(conn, "%s\r\n", password); writeErr != nil {
		result.Error = brutus.WrapConnError(writeErr)
		return result
	}

	postPassword, err := readResponse(conn, reader, timeout)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	result.Error = classifyTelnetResponse(postPassword)
	if result.Error == nil && isSuccessIndicator(postPassword) {
		result.Success = true
	}

	return result
}

var classifyError = brutus.NewClassifier(telnetAuthIndicators)

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

// readResponse reads the post-password response.
//
// It reads until the stream is idle for responseSettleWindow, the peer closes
// the connection, the overall timeout elapses, or the buffer fills. It does not
// bail out the instant a success prompt or failure keyword appears: a banner may
// contain "failed" before the real prompt, and a stray prompt may be followed by
// "Login incorrect". Capturing the settled response lets classifyTelnetResponse
// and isSuccessIndicator judge the final relevant line.
func readResponse(conn net.Conn, reader *bufio.Reader, timeout time.Duration) (string, error) {
	buffer := make([]byte, 0, 4096)
	overall := time.Now().Add(timeout)

	for {
		remaining := time.Until(overall)
		if remaining <= 0 {
			break
		}

		window := responseSettleWindow
		if window > remaining {
			window = remaining
		}
		_ = conn.SetReadDeadline(time.Now().Add(window))

		b, err := reader.ReadByte()
		if err != nil {
			var netErr net.Error
			switch {
			case errors.Is(err, io.EOF):
				if len(buffer) > 0 {
					return string(buffer), nil
				}
				return "", fmt.Errorf("unexpected EOF")
			case errors.As(err, &netErr) && netErr.Timeout():
				// Idle for the settle window: if we have data the response has
				// settled; otherwise keep waiting until the overall deadline.
				if len(buffer) > 0 {
					return string(buffer), nil
				}
				continue
			default:
				if len(buffer) > 0 {
					return string(buffer), nil
				}
				return "", err
			}
		}

		buffer = append(buffer, b)

		// Prevent buffer overflow
		if len(buffer) >= 4096 {
			break
		}
	}

	return string(buffer), nil
}

// classifyTelnetResponse classifies the post-password Telnet response.
//
// Auth failure indicators (return nil):
// - "incorrect", "failed", "denied", "invalid" (via shared telnetAuthIndicators)
//
// Success indicators (return nil):
// - Shell prompts ($, #, or >) at end of line
//
// All other errors are connection problems (return wrapped error).
func classifyTelnetResponse(response string) error {
	if response == "" {
		return fmt.Errorf("connection error: empty response")
	}

	respLower := strings.ToLower(response)

	if strings.Contains(respLower, "connection closed") {
		return fmt.Errorf("connection error: connection closed")
	}

	if isSuccessIndicator(response) {
		return nil
	}

	responseErr := errors.New(response)
	if brutus.ClassifyAuthError(responseErr, telnetAuthIndicators) == nil {
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

// isSuccessIndicator checks if the post-password response indicates successful
// authentication. Success is a $, #, or > shell prompt at the end of a line.
//
// The verdict follows the final relevant line: an auth-failure indicator (e.g.
// "Login incorrect") appearing on or after a prompt-like line overrides that
// prompt, so a stray prompt earlier in the response (such as "router>\nLogin
// incorrect") is not misread as success.
func isSuccessIndicator(response string) bool {
	success := false
	for _, line := range strings.Split(response, "\n") {
		if containsAuthFailureIndicator(line) {
			success = false
			continue
		}
		if isPromptLine(line) {
			success = true
		}
	}
	return success
}

func isPromptLine(line string) bool {
	line = ansiCSIPattern.ReplaceAllString(line, "")
	line = strings.TrimRight(line, "\r\n\t ")
	if line == "" {
		return false
	}

	last := line[len(line)-1]
	if last != '$' && last != '#' && last != '>' {
		return false
	}
	// Reject '#' banner/box lines (multiple '#'), which are MOTD decoration
	// rather than a shell prompt.
	if last == '#' && strings.Count(line, "#") > 1 {
		return false
	}
	return true
}

// containsAuthFailureIndicator checks if the response contains any auth failure indicator.
func containsAuthFailureIndicator(response string) bool {
	lower := strings.ToLower(response)
	for _, indicator := range telnetAuthIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}
