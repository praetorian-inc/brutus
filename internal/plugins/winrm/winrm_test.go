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

package winrm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/masterzen/winrm"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	t.Run("winrm", func(t *testing.T) {
		p := &Plugin{UseHTTPS: false}
		assert.Equal(t, "winrm", p.Name())
	})

	t.Run("winrms", func(t *testing.T) {
		p := &Plugin{UseHTTPS: true}
		assert.Equal(t, "winrms", p.Name())
	})
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		// want: "nil" = auth failure, "auth_success" = SOAP fault (valid creds), "connection_error" = connection problem
		want string
	}{
		{
			name: "nil error",
			err:  nil,
			want: "nil",
		},
		{
			name: "http error 401",
			err:  errors.New("http error 401: Unauthorized"),
			want: "nil",
		},
		{
			name: "http response error 401",
			err:  errors.New("http response error: 401"),
			want: "nil",
		},
		{
			name: "SOAP fault (AccessDenied)",
			err:  &winrm.ExecuteCommandError{Inner: errors.New("received error response"), Body: "<Fault>AccessDenied</Fault>"},
			want: "auth_success",
		},
		{
			name: "SOAP fault (other)",
			err:  &winrm.ExecuteCommandError{Inner: errors.New("received error response"), Body: "<Fault>SomethingElse</Fault>"},
			want: "auth_success",
		},
		{
			name: "connection refused",
			err:  errors.New("dial tcp: connection refused"),
			want: "connection_error",
		},
		{
			name: "timeout",
			err:  errors.New("dial tcp: i/o timeout"),
			want: "connection_error",
		},
		{
			name: "dns error",
			err:  errors.New("dial tcp: lookup invalid.host: no such host"),
			want: "connection_error",
		},
		{
			name: "http error 500",
			err:  errors.New("http error 500: Internal Server Error"),
			want: "connection_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyError(tt.err)
			switch tt.want {
			case "nil":
				assert.Nil(t, result)
			case "auth_success":
				assert.ErrorIs(t, result, errAuthSuccess)
			case "connection_error":
				assert.NotNil(t, result)
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		useHTTPS bool
		wantHost string
		wantPort int
	}{
		{
			name:     "host with port",
			target:   "192.168.1.1:5985",
			useHTTPS: false,
			wantHost: "192.168.1.1",
			wantPort: 5985,
		},
		{
			name:     "host without port HTTP",
			target:   "192.168.1.1",
			useHTTPS: false,
			wantHost: "192.168.1.1",
			wantPort: 5985,
		},
		{
			name:     "host without port HTTPS",
			target:   "192.168.1.1",
			useHTTPS: true,
			wantHost: "192.168.1.1",
			wantPort: 5986,
		},
		{
			name:     "host with custom port",
			target:   "10.0.0.1:8080",
			useHTTPS: false,
			wantHost: "10.0.0.1",
			wantPort: 8080,
		},
		{
			name:     "hostname with port",
			target:   "winserver.local:5985",
			useHTTPS: false,
			wantHost: "winserver.local",
			wantPort: 5985,
		},
		{
			name:     "hostname without port",
			target:   "winserver.local",
			useHTTPS: false,
			wantHost: "winserver.local",
			wantPort: 5985,
		},
		{
			name:     "IPv6 with port",
			target:   "[::1]:5985",
			useHTTPS: false,
			wantHost: "::1",
			wantPort: 5985,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := parseTarget(tt.target, tt.useHTTPS)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have WinRM running
	result := p.Test(ctx, "localhost:9999", "admin", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrm", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	timeout := 2 * time.Second

	result := p.Test(ctx, "invalid.host.nonexistent:5985", "admin", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrm", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()

	// Use blackhole IP that won't respond
	result := p.Test(ctx, "192.0.2.1:5985", "admin", "password", 1*time.Second)

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	p := &Plugin{UseHTTPS: false}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	result := p.Test(ctx, "localhost:5985", "admin", "password", 5*time.Second)

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Target without port should use default 5985
	result := p.Test(ctx, "localhost", "admin", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrm", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_HTTPS(t *testing.T) {
	p := &Plugin{UseHTTPS: true}
	ctx := context.Background()
	timeout := 2 * time.Second

	// HTTPS variant should use "winrms" protocol name
	result := p.Test(ctx, "localhost:9999", "admin", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrms", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	// Skip if no WinRM server available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Skip("Integration test - requires WinRM server")

	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, "localhost:5985", "Administrator", "password", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrm", result.Protocol)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	// Skip if no WinRM server available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	t.Skip("Integration test - requires WinRM server")

	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, "localhost:5985", "Administrator", "wrongpassword", timeout)

	assert.NotNil(t, result)
	assert.Equal(t, "winrm", result.Protocol)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestInit(t *testing.T) {
	// Verify both winrm and winrms are registered via init()
	p1, err := brutus.GetPlugin("winrm")
	assert.NoError(t, err)
	assert.NotNil(t, p1)
	assert.Equal(t, "winrm", p1.Name())

	p2, err := brutus.GetPlugin("winrms")
	assert.NoError(t, err)
	assert.NotNil(t, p2)
	assert.Equal(t, "winrms", p2.Name())
}
