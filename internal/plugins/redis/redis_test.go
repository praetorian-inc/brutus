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

package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// getTestConfig returns test configuration from environment variables with defaults
func getTestConfig() (host, pass string) {
	host = os.Getenv("REDIS_TEST_HOST")
	if host == "" {
		host = "localhost:6379"
	}
	pass = os.Getenv("REDIS_TEST_PASS")
	if pass == "" {
		pass = "testpassword"
	}
	return
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "redis", p.Name())
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool // true if should be classified as auth error (nil)
	}{
		{
			name:     "noauth",
			errStr:   "NOAUTH Authentication required",
			wantAuth: true,
		},
		{
			name:     "wrongpass",
			errStr:   "WRONGPASS invalid username-password pair",
			wantAuth: true,
		},
		{
			name:     "invalid password",
			errStr:   "invalid password",
			wantAuth: true,
		},
		{
			name:     "err invalid password",
			errStr:   "ERR invalid password",
			wantAuth: true,
		},
		{
			name:     "err client sent auth",
			errStr:   "ERR Client sent AUTH, but no password is set",
			wantAuth: true,
		},
		{
			name:     "without any password",
			errStr:   "without any password configured",
			wantAuth: true,
		},
		{
			name:     "connection error",
			errStr:   "connection refused",
			wantAuth: false,
		},
		{
			name:     "network error",
			errStr:   "no route to host",
			wantAuth: false,
		},
		{
			name:     "timeout error",
			errStr:   "context deadline exceeded",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &mockError{msg: tt.errStr}
			result := classifyError(err)

			if tt.wantAuth {
				assert.Nil(t, result, "auth errors should return nil")
			} else {
				assert.NotNil(t, result, "connection errors should be wrapped")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	if os.Getenv("REDIS_TEST_HOST") == "" {
		t.Skip("Integration test - requires Redis server (set REDIS_TEST_HOST)")
	}

	host, pass := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, "", pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success, "Expected successful authentication")
	assert.Nil(t, result.Error, "Expected no error on successful auth")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	if os.Getenv("REDIS_TEST_HOST") == "" {
		t.Skip("Integration test - requires Redis server (set REDIS_TEST_HOST)")
	}

	host, _ := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, "", "wrongpassword", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success, "Expected failed authentication")
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_NoAuthRequired(t *testing.T) {
	if os.Getenv("REDIS_TEST_HOST") == "" {
		t.Skip("Integration test - requires Redis server without auth (set REDIS_TEST_HOST)")
	}

	host, _ := getTestConfig()

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	// Try empty password on Redis with no auth required
	result := p.Test(ctx, host, "", "", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, "", result.Password)
	// If Redis has no auth, this should succeed
	// If Redis requires auth, this should fail with nil error (auth failure)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have Redis running
	result := p.Test(ctx, "localhost:9999", "", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "Connection error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use an invalid hostname
	result := p.Test(ctx, "127.0.0.1:1", "", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "DNS error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Very short timeout to force timeout error
	timeout := 1 * time.Nanosecond

	result := p.Test(ctx, "localhost:6379", "", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected timeout failure")
	assert.NotNil(t, result.Error, "Timeout should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if os.Getenv("REDIS_TEST_HOST") == "" {
		t.Skip("Integration test - requires Redis server (set REDIS_TEST_HOST)")
	}

	host, pass := getTestConfig()

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	timeout := 5 * time.Second

	result := p.Test(ctx, host, "", pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected context cancellation failure")
	assert.NotNil(t, result.Error, "Context cancellation should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Target without port (should use default 6379 or fail)
	result := p.Test(ctx, "localhost", "", "password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "redis", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	// Connection may fail or succeed depending on implementation
	// Just verify we get a valid result structure
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_UnbracketedIPv6(t *testing.T) {
	p := &Plugin{}
	result := p.Test(context.Background(), "::1", "", "pass", 200*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	if result.Error != nil {
		assert.NotContains(t, result.Error.Error(), "too many colons")
	}
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	p := &Plugin{}
	result := p.Test(context.Background(), "127.0.0.1:6379", "", "pass", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	// Just verify the plugin can be instantiated
	p := &Plugin{}
	assert.NotNil(t, p)
	assert.Equal(t, "redis", p.Name())
}

func TestPlugin_CheckUnauth_Open(t *testing.T) {
	addr := mockRedis(t, false)
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 2*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Contains(t, r.Banner, "CRITICAL")
	assert.Contains(t, r.Banner, "7.2.0")
}

func TestPlugin_CheckUnauth_RequiresAuth(t *testing.T) {
	addr := mockRedis(t, true)
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func TestPlugin_CheckUnauth_ClosedPort(t *testing.T) {
	r := (&Plugin{}).CheckUnauth(context.Background(), "127.0.0.1:1", 500*time.Millisecond, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func mockRedis(t *testing.T, requireAuth bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRedis(conn, requireAuth)
		}
	}()
	return ln.Addr().String()
}

func serveRedis(conn net.Conn, requireAuth bool) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	for {
		cmd, err := readRedisCommand(r)
		if err != nil {
			return
		}
		switch cmd {
		case "HELLO":
			_, _ = io.WriteString(conn, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			if requireAuth {
				_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
				continue
			}
			_, _ = io.WriteString(conn, "+PONG\r\n")
		case "INFO":
			if requireAuth {
				_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
				continue
			}
			payload := "redis_version:7.2.0\r\n"
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(payload), payload)
		default:
			if requireAuth {
				_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
			} else {
				_, _ = io.WriteString(conn, "+OK\r\n")
			}
		}
	}
}

func readRedisCommand(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "*") {
		return strings.ToUpper(strings.TrimSpace(line)), nil
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 1 {
		return "", fmt.Errorf("bad RESP array")
	}
	var name string
	for i := 0; i < n; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		lenLine = strings.TrimSpace(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			return "", fmt.Errorf("bad RESP bulk")
		}
		size, err := strconv.Atoi(lenLine[1:])
		if err != nil {
			return "", err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		if i == 0 {
			name = strings.ToUpper(string(buf[:size]))
		}
	}
	return name, nil
}

// mockError is a simple error implementation for testing error classification
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
