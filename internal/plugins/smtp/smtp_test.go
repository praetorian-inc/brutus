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
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var (
	smtpTestHost = os.Getenv("SMTP_TEST_HOST")
	smtpTestUser = os.Getenv("SMTP_TEST_USER")
	smtpTestPass = os.Getenv("SMTP_TEST_PASS")
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "smtp", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	if smtpTestHost == "" {
		t.Skip("Integration test - requires SMTP server (set SMTP_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, smtpTestHost, smtpTestUser, smtpTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, smtpTestHost, result.Target)
	assert.Equal(t, smtpTestUser, result.Username)
	assert.Equal(t, smtpTestPass, result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	if smtpTestHost == "" {
		t.Skip("Integration test - requires SMTP server (set SMTP_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, smtpTestHost, smtpTestUser, "definitely-wrong-password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, smtpTestHost, result.Target)
	assert.Equal(t, smtpTestUser, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "user@example.com", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smtp", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:25", "u", "p", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example", TLSMode: "disable"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if smtpTestHost == "" {
		t.Skip("Integration test - requires SMTP server (set SMTP_TEST_HOST)")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, smtpTestHost, smtpTestUser, smtpTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:587", "user@example.com", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestClassifyError_AuthenticationFailure(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected error
	}{
		{
			name:     "535 authentication failed",
			errMsg:   "535 5.7.8 Error: authentication failed",
			expected: nil, // Auth failure returns nil
		},
		{
			name:     "535 Authentication credentials invalid",
			errMsg:   "535 Authentication credentials invalid",
			expected: nil,
		},
		{
			name:     "invalid username or password",
			errMsg:   "invalid username or password",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple error with the message
			testErr := &mockError{msg: tt.errMsg}
			result := classifyError(testErr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClassifyError_ConnectionError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{
			name:   "connection refused",
			errMsg: "connection refused",
		},
		{
			name:   "timeout",
			errMsg: "i/o timeout",
		},
		{
			name:   "tls handshake failed",
			errMsg: "tls: handshake failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testErr := &mockError{msg: tt.errMsg}
			result := classifyError(testErr)
			assert.NotNil(t, result)
			assert.Contains(t, result.Error(), "connection error")
		})
	}
}

// mockError is a simple error implementation for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func mockSMTPServer(t *testing.T, advertiseSTARTTLS bool, sawSTARTTLS, sawAuth *bool) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		_, _ = fmt.Fprint(conn, "220 localhost ESMTP\r\n")
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				if advertiseSTARTTLS {
					_, _ = fmt.Fprint(conn, "250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n")
				} else {
					_, _ = fmt.Fprint(conn, "250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
				}
			case strings.HasPrefix(cmd, "STARTTLS"):
				*sawSTARTTLS = true
				_, _ = fmt.Fprint(conn, "454 TLS not available\r\n")
			case strings.HasPrefix(cmd, "AUTH"):
				*sawAuth = true
				_, _ = fmt.Fprint(conn, "535 Authentication failed\r\n")
			case strings.HasPrefix(cmd, "QUIT"):
				_, _ = fmt.Fprint(conn, "221 Bye\r\n")
				return
			default:
				_, _ = fmt.Fprint(conn, "502 Not implemented\r\n")
			}
		}
	}()

	cleanup = func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), cleanup
}

func TestPlugin_STARTTLS(t *testing.T) {
	tests := []struct {
		name              string
		tlsMode           string
		advertiseSTARTTLS bool
		wantSTARTTLS      bool
		wantAuth          bool
		wantErrContains   string
	}{
		{
			name:              "verify without STARTTLS does not send credentials",
			tlsMode:           "verify",
			advertiseSTARTTLS: false,
			wantSTARTTLS:      false,
			wantAuth:          false,
			wantErrContains:   "STARTTLS",
		},
		{
			name:              "opportunistic STARTTLS in default mode",
			tlsMode:           "",
			advertiseSTARTTLS: true,
			wantSTARTTLS:      true,
			wantAuth:          false,
			wantErrContains:   "STARTTLS",
		},
		{
			name:              "disable without STARTTLS still authenticates",
			tlsMode:           "disable",
			advertiseSTARTTLS: false,
			wantSTARTTLS:      false,
			wantAuth:          true,
		},
		{
			name:              "disable does not attempt STARTTLS even when advertised",
			tlsMode:           "disable",
			advertiseSTARTTLS: true,
			wantSTARTTLS:      false,
			wantAuth:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sawSTARTTLS, sawAuth bool
			addr, cleanup := mockSMTPServer(t, tt.advertiseSTARTTLS, &sawSTARTTLS, &sawAuth)

			p := &Plugin{}
			result := p.Test(context.Background(), addr, "user", "pass", 5*time.Second, brutus.PluginConfig{TLSMode: tt.tlsMode})
			cleanup()

			assert.False(t, result.Success)
			assert.Equal(t, tt.wantSTARTTLS, sawSTARTTLS)
			assert.Equal(t, tt.wantAuth, sawAuth)
			if tt.wantErrContains == "" {
				assert.Nil(t, result.Error)
			} else {
				require.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "connection error")
				assert.Contains(t, result.Error.Error(), tt.wantErrContains)
			}
		})
	}
}
