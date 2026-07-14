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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// startStallingServer starts a TCP listener that accepts connections but
// never writes anything (no protocol banner), simulating a server that
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
	assert.Equal(t, "vnc", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no VNC server available
	// In real tests, use Docker container with known credentials
	t.Skip("Integration test - requires VNC server")

	p := &Plugin{}
	ctx := context.Background()

	// VNC uses password-only authentication (no username)
	result := p.Test(ctx, "localhost:5900", "", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "vnc", result.Protocol)
	assert.Equal(t, "localhost:5900", result.Target)
	assert.Equal(t, "", result.Username) // VNC doesn't use username
	assert.Equal(t, "password", result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no VNC server available
	t.Skip("Integration test - requires VNC server")

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:5900", "", "wrongpassword", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "vnc", result.Protocol)
	assert.Equal(t, "localhost:5900", result.Target)
	assert.Equal(t, "", result.Username)
	assert.Equal(t, "wrongpassword", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "vnc", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	t.Skip("Integration test - requires VNC server")

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, "localhost:5900", "", "password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

// TestPlugin_Test_StalledHandshakeDoesNotHang is a regression test proving
// that a server which accepts the TCP connection but never speaks (no VNC
// protocol banner) does not hang Test() forever. Without SetDeadline on the
// dialed conn, vnc.Client's blocking read would stall indefinitely.
func TestPlugin_Test_StalledHandshakeDoesNotHang(t *testing.T) {
	p := &Plugin{}
	target := startStallingServer(t)

	done := make(chan struct{})
	var result *brutus.Result
	go func() {
		result = p.Test(context.Background(), target, "", "password", 500*time.Millisecond, brutus.PluginConfig{})
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

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:5900", "", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}
