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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "telnet", p.Name())
}

func TestClassifyError(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.1:23: connection refused")
	result := classifyError(err)

	assert.NotNil(t, result)
	assert.Contains(t, result.Error(), "connection error")
	assert.Contains(t, result.Error(), "connection refused")
}

func TestClassifyTelnetResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantNil  bool // true = auth failure (return nil), false = connection error (return error)
	}{
		{
			name:     "auth failure - Login incorrect",
			response: "Login incorrect\n",
			wantNil:  true,
		},
		{
			name:     "auth failure - Authentication failed",
			response: "Authentication failed\n",
			wantNil:  true,
		},
		{
			name:     "auth failure - Access denied",
			response: "Access denied\n",
			wantNil:  true,
		},
		{
			name:     "auth failure - Invalid credentials",
			response: "Invalid credentials\n",
			wantNil:  true,
		},
		{
			name:     "auth failure - incorrect (lowercase)",
			response: "login incorrect\n",
			wantNil:  true,
		},
		{
			name:     "success - shell prompt $",
			response: "user@host:~$ ",
			wantNil:  true,
		},
		{
			name:     "success - shell prompt #",
			response: "[root@host ~]# ",
			wantNil:  true,
		},
		{
			name:     "success - simple $ prompt",
			response: "$ ",
			wantNil:  true,
		},
		{
			name:     "success - simple # prompt",
			response: "# ",
			wantNil:  true,
		},
		{
			name:     "connection error - EOF",
			response: "",
			wantNil:  false,
		},
		{
			name:     "connection error - Connection closed",
			response: "Connection closed by foreign host\n",
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyTelnetResponse(tt.response)
			if tt.wantNil {
				assert.Nil(t, result, "auth failure or success should return nil")
			} else {
				assert.NotNil(t, result, "connection error should return error")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestIsLoginPrompt(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
		want   bool
	}{
		{"lowercase login:", "login: ", true},
		{"capitalized Login:", "Login: ", true},
		{"uppercase LOGIN:", "LOGIN: ", true},
		{"Username:", "Username: ", true},
		{"username:", "username: ", true},
		{"User:", "User: ", true},
		{"user:", "user: ", true},
		{"not a login prompt", "Welcome to server\n", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLoginPrompt(tt.prompt))
		})
	}
}

func TestIsPasswordPrompt(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
		want   bool
	}{
		{"lowercase password:", "password: ", true},
		{"capitalized Password:", "Password: ", true},
		{"uppercase PASSWORD:", "PASSWORD: ", true},
		{"Pass:", "Pass: ", true},
		{"pass:", "pass: ", true},
		{"not a password prompt", "Welcome to server\n", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPasswordPrompt(tt.prompt))
		})
	}
}

func TestIsSuccessIndicator(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     bool
	}{
		{"shell prompt with $", "user@host:~$ ", true},
		{"shell prompt with #", "[root@host ~]# ", true},
		{"simple $ prompt", "$ ", true},
		{"simple # prompt", "# ", true},
		{"$ at end of line", "Last login: Mon Jan 14 12:00:00 2026\n$ ", true},
		{"# at end of line", "Last login: Mon Jan 14 12:00:00 2026\n# ", true},
		{"no prompt", "Welcome to server\n", false},
		{"$ in middle", "Cost is $100\n", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSuccessIndicator(tt.response))
		})
	}
}

func TestIsFailureIndicator(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     bool
	}{
		{"Login incorrect", "Login incorrect\n", true},
		{"login incorrect (lowercase)", "login incorrect\n", true},
		{"Authentication failed", "Authentication failed\n", true},
		{"authentication failed (lowercase)", "authentication failed\n", true},
		{"Access denied", "Access denied\n", true},
		{"access denied (lowercase)", "access denied\n", true},
		{"Invalid credentials", "Invalid credentials\n", true},
		{"invalid (lowercase)", "invalid login\n", true},
		{"Permission denied", "Permission denied\n", true},
		{"success prompt", "$ ", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isFailureIndicator(tt.response))
		})
	}
}
