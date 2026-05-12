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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

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
