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

package ssh

import (
	"context"
	"errors"
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
	assert.Equal(t, "ssh", p.Name())
}

func TestClassifyError(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.1:22: connection refused")
	result := brutus.WrapConnError(err)

	assert.NotNil(t, result)
	assert.Contains(t, result.Error(), "connection error")
	assert.Contains(t, result.Error(), "connection refused")
}

func TestClassifyAuthError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantNil bool // true = auth failure (return nil), false = connection error (return error)
	}{
		{
			name:    "auth failure - unable to authenticate",
			err:     errors.New("ssh: unable to authenticate, attempted methods [none password], no supported methods remain"),
			wantNil: true,
		},
		{
			name:    "auth failure - permission denied",
			err:     errors.New("ssh: handshake failed: ssh: permission denied"),
			wantNil: true,
		},
		{
			name:    "auth failure - no supported methods remain",
			err:     errors.New("ssh: no supported methods remain"),
			wantNil: true,
		},
		{
			name:    "connection error - timeout",
			err:     errors.New("dial tcp 10.0.0.1:22: i/o timeout"),
			wantNil: false,
		},
		{
			name:    "connection error - connection refused",
			err:     errors.New("dial tcp 10.0.0.1:22: connection refused"),
			wantNil: false,
		},
		{
			name:    "connection error - network unreachable",
			err:     errors.New("dial tcp 10.0.0.1:22: network is unreachable"),
			wantNil: false,
		},
		{
			name:    "connection error - host unreachable",
			err:     errors.New("dial tcp 10.0.0.1:22: no route to host"),
			wantNil: false,
		},
		{
			name:    "nil error",
			err:     nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyAuthError(tt.err)
			if tt.wantNil {
				assert.Nil(t, result, "auth failure should return nil")
			} else {
				assert.NotNil(t, result, "connection error should return error")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

// TestPlugin_Test_StalledHandshakeDoesNotHang is a regression test proving that
// a server which accepts the TCP connection but never speaks (no SSH banner)
// does not hang Test() forever. Without SetDeadline on the dialed conn, the
// SSH handshake would block indefinitely on the stalled read.
func TestPlugin_Test_StalledHandshakeDoesNotHang(t *testing.T) {
	plugin := &Plugin{}
	target := startStallingServer(t)

	done := make(chan struct{})
	var result *brutus.Result
	go func() {
		result = plugin.Test(context.Background(), target, "testuser", "testpass", 500*time.Millisecond, brutus.PluginConfig{})
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

// Integration test for password authentication - requires real SSH server (skipped by default)
func TestPlugin_Test_Integration(t *testing.T) {
	t.Skip("Integration test requires SSH server with password auth configured")

	// This test would verify actual SSH password authentication
	// against a real SSH server.
	//
	// Setup:
	// 1. Start SSH server (e.g., Docker container: openssh-server)
	// 2. Configure server with test user/password
	// 3. Test authentication with valid credentials
	// 4. Test authentication with invalid credentials
	//
	// Expected:
	// - Valid credentials: Success=true, Error=nil
	// - Invalid credentials: Success=false, Error=nil (auth failure)
	// - Connection error: Success=false, Error!=nil
}
