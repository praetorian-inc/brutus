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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptChunk is a piece of data a scriptedConn delivers once the elapsed time
// since the connection was created reaches availableAt.
type scriptChunk struct {
	availableAt time.Duration
	data        string
}

// scriptedConn is a minimal net.Conn test double that delivers scripted chunks
// on a timeline and honors read deadlines, so readResponse's settle behavior can
// be exercised deterministically.
type scriptedConn struct {
	chunks       []scriptChunk
	idx          int
	start        time.Time
	readDeadline time.Time
}

func newScriptedConn(chunks []scriptChunk) *scriptedConn {
	return &scriptedConn{chunks: chunks, start: time.Now()}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		// No more data: block until the read deadline, then report a timeout so
		// the caller can treat the stream as settled.
		if !c.readDeadline.IsZero() {
			if d := time.Until(c.readDeadline); d > 0 {
				time.Sleep(d)
			}
			return 0, timeoutError{}
		}
		return 0, io.EOF
	}

	chunk := c.chunks[c.idx]
	availableAt := c.start.Add(chunk.availableAt)
	if now := time.Now(); now.Before(availableAt) {
		if !c.readDeadline.IsZero() && c.readDeadline.Before(availableAt) {
			if d := time.Until(c.readDeadline); d > 0 {
				time.Sleep(d)
			}
			return 0, timeoutError{}
		}
		time.Sleep(time.Until(availableAt))
	}

	n := copy(p, chunk.data)
	c.idx++
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *scriptedConn) Close() error                { return nil }
func (c *scriptedConn) LocalAddr() net.Addr         { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr        { return nil }
func (c *scriptedConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *scriptedConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestReadResponse_CapturesPromptArrivingAfterMOTDFailure(t *testing.T) {
	// A banner containing "failed" arrives first, and the real shell prompt
	// arrives more than 100ms later. readResponse must keep reading through the
	// settle window rather than bailing on the failure keyword mid-banner.
	conn := newScriptedConn([]scriptChunk{
		{availableAt: 0, data: "failed to mount /data\r\n"},
		{availableAt: 150 * time.Millisecond, data: "user@host:~$ "},
	})

	resp, err := readResponse(conn, bufio.NewReader(conn), 3*time.Second)

	require.NoError(t, err)
	assert.Contains(t, resp, "user@host:~$")
	assert.True(t, isSuccessIndicator(resp), "late-arriving prompt should be captured and classified as success")
}

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
			name:     "success - > prompt",
			response: "router>",
			wantNil:  true,
		},
		{
			name:     "success - prompt after motd containing failed",
			response: "failed to mount /data\nuser@host:~$ ",
			wantNil:  true,
		},
		{
			name:     "auth failure - motd hashes then incorrect",
			response: "################################\nLogin incorrect\n",
			wantNil:  true,
		},
		{
			name:     "auth failure - prompt then Login incorrect",
			response: "router>\nLogin incorrect\n",
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
		{"> prompt", "router>", true},
		{"windows prompt", "C:\\>", true},
		{"failed in motd then prompt", "failed to mount /data\nuser@host:~$ ", true},
		{"prompt then Login incorrect", "router>\nLogin incorrect\n", false},
		{"cisco config prompt", "Router(config)#", true},
		{"cisco config-if prompt trailing space", "Router(config-if)# ", true},
		{"ansi colored prompt", "\x1b[32muser@host:~\x1b[0m$ ", true},
		{"prompt with trailing ansi cursor query", "user@host:~$ \x1b[6n", true},
		{"no prompt", "Welcome to server\n", false},
		{"$ in middle", "Cost is $100\n", false},
		{"MOTD hash comment", "# Welcome to the gateway\n", false},
		{"MOTD hash banner", "################################\n", false},
		{"MOTD hash box line", "# Welcome to the server #\n", false},
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
			assert.Equal(t, tt.want, containsAuthFailureIndicator(tt.response))
		})
	}
}
