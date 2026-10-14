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

package smb

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// startStallingServer starts a TCP listener that accepts connections but
// never writes anything (no SMB negotiate response), simulating a server that
// stalls the handshake. It returns the listener's address as the target.
func startStallingServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start stalling server: %v", err)
	}

	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "smb", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	host := os.Getenv("SMB_TEST_HOST")
	if host == "" {
		t.Skip("Integration test - requires SMB server (set SMB_TEST_HOST)")
	}
	user := os.Getenv("SMB_TEST_USER")
	pass := os.Getenv("SMB_TEST_PASS")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, host, user, pass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	host := os.Getenv("SMB_TEST_HOST")
	if host == "" {
		t.Skip("Integration test - requires SMB server (set SMB_TEST_HOST)")
	}
	user := os.Getenv("SMB_TEST_USER")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, host, user, "definitely-wrong-password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "Administrator", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:445", "Administrator", "password", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "Administrator", "password", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	host := os.Getenv("SMB_TEST_HOST")
	if host == "" {
		t.Skip("Integration test - requires SMB server (set SMB_TEST_HOST)")
	}
	user := os.Getenv("SMB_TEST_USER")
	pass := os.Getenv("SMB_TEST_PASS")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, host, user, pass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:445", "Administrator", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

// TestPlugin_Test_StalledHandshakeDoesNotHang is a regression test proving that
// a server which accepts the TCP connection but never speaks (no SMB negotiate)
// does not hang Test() forever. Without SetDeadline on the dialed conn, the
// SMB handshake would block indefinitely on the stalled read.
func TestPlugin_Test_StalledHandshakeDoesNotHang(t *testing.T) {
	p := &Plugin{}
	target := startStallingServer(t)

	done := make(chan struct{})
	var result *brutus.Result
	go func() {
		result = p.Test(context.Background(), target, "Administrator", "password", 500*time.Millisecond, brutus.PluginConfig{})
		close(done)
	}()

	select {
	case <-done:
		// completed - good
	case <-time.After(5 * time.Second):
		t.Fatal("Test() did not return within 5s - handshake deadline missing (regressed)")
	}

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Error(t, result.Error)
}

func TestPlugin_Test_DomainUsername(t *testing.T) {
	host := os.Getenv("SMB_TEST_HOST")
	if host == "" {
		t.Skip("Integration test - requires SMB server with domain (set SMB_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	// Test with DOMAIN\username format
	// NOTE: "DOMAIN\Administrator"/"password" are hardcoded since there is no
	// SMB_TEST_DOMAIN env var - this assumes the SMB_TEST_HOST server is
	// configured with this exact domain account. Uncertain against real servers.
	result := p.Test(ctx, host, "DOMAIN\\Administrator", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, "DOMAIN\\Administrator", result.Username)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_Test_IPv6Target(t *testing.T) {
	if os.Getenv("SMB_TEST_HOST") != "" {
		t.Skip("SMB service is running; IPv6 loopback on port 445 reaches the Docker container")
	}

	p := &Plugin{}
	ctx := context.Background()

	// Test IPv6 address with port - should fail connection but parse correctly
	result := p.Test(ctx, "[::1]:445", "Administrator", "password", 1*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "[::1]:445", result.Target)
	assert.Equal(t, "Administrator", result.Username)
	assert.False(t, result.Success) // Will fail to connect but should parse correctly
	assert.NotNil(t, result.Error)  // Connection error expected
}

func TestPlugin_Test_IPv6TargetNoPort(t *testing.T) {
	if os.Getenv("SMB_TEST_HOST") != "" {
		t.Skip("SMB service is running; IPv6 loopback on default port 445 reaches the Docker container")
	}

	p := &Plugin{}
	ctx := context.Background()

	// Test IPv6 address without port - should default to 445
	result := p.Test(ctx, "::1", "Administrator", "password", 1*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "smb", result.Protocol)
	assert.Equal(t, "::1", result.Target)
	assert.Equal(t, "Administrator", result.Username)
	assert.False(t, result.Success) // Will fail to connect but should parse correctly
	assert.NotNil(t, result.Error)  // Connection error expected
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		expectedHost string
		expectedPort string
	}{
		{
			name:         "IPv4 with port",
			target:       "192.168.1.1:445",
			expectedHost: "192.168.1.1",
			expectedPort: "445",
		},
		{
			name:         "IPv4 without port",
			target:       "192.168.1.1",
			expectedHost: "192.168.1.1",
			expectedPort: "445",
		},
		{
			name:         "hostname with port",
			target:       "example.com:139",
			expectedHost: "example.com",
			expectedPort: "139",
		},
		{
			name:         "hostname without port",
			target:       "example.com",
			expectedHost: "example.com",
			expectedPort: "445",
		},
		{
			name:         "IPv6 with port",
			target:       "[::1]:445",
			expectedHost: "::1",
			expectedPort: "445",
		},
		{
			name:         "IPv6 without port",
			target:       "::1",
			expectedHost: "::1",
			expectedPort: "445",
		},
		{
			name:         "IPv6 full address with port",
			target:       "[2001:db8::1]:445",
			expectedHost: "2001:db8::1",
			expectedPort: "445",
		},
		{
			name:         "IPv6 full address without port",
			target:       "2001:db8::1",
			expectedHost: "2001:db8::1",
			expectedPort: "445",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := brutus.ParseTarget(tt.target, "445")
			assert.Equal(t, tt.expectedHost, host, "host mismatch for target %s", tt.target)
			assert.Equal(t, tt.expectedPort, port, "port mismatch for target %s", tt.target)
		})
	}
}
