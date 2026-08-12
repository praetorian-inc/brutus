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

package pop3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "pop3", p.Name())
}

func TestClassifyError(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.1:110: connection refused")
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
			name:    "auth failure - -ERR",
			err:     errors.New("-ERR Invalid credentials"),
			wantNil: true,
		},
		{
			name:    "auth failure - -ERR [AUTH] Authentication failed",
			err:     errors.New("-ERR [AUTH] Authentication failed"),
			wantNil: true,
		},
		{
			name:    "auth failure - -ERR Login failed",
			err:     errors.New("-ERR Login failed"),
			wantNil: true,
		},
		{
			name:    "auth failure - -ERR with lowercase",
			err:     errors.New("-err invalid login"),
			wantNil: true,
		},
		{
			name:    "connection error - timeout",
			err:     errors.New("dial tcp 10.0.0.1:110: i/o timeout"),
			wantNil: false,
		},
		{
			name:    "connection error - connection refused",
			err:     errors.New("dial tcp 10.0.0.1:110: connection refused"),
			wantNil: false,
		},
		{
			name:    "connection error - network unreachable",
			err:     errors.New("dial tcp 10.0.0.1:110: network is unreachable"),
			wantNil: false,
		},
		{
			name:    "connection error - EOF",
			err:     errors.New("EOF"),
			wantNil: false,
		},
		{
			name:    "connection error - read error",
			err:     errors.New("read tcp 10.0.0.1:110: connection reset by peer"),
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

// mockPOP3Server starts a TCP listener that speaks a scripted POP3 conversation.
// handler receives the server-side conn and a reader for consuming client commands.
func mockPOP3Server(t *testing.T, handler func(conn net.Conn, reader *bufio.Reader)) (addr string, cleanup func()) {
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
		handler(conn, reader)
	}()

	cleanup = func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), cleanup
}

// pop3Send writes a POP3 response line to the connection.
func pop3Send(conn net.Conn, msg string) {
	_, _ = fmt.Fprint(conn, msg)
}

// pop3Recv reads one line from the connection (a client command), returning
// ok=false if the connection was closed/errored before a line arrived. This
// lets tests distinguish "no command sent" from "command sent".
func pop3Recv(reader *bufio.Reader) (cmd string, ok bool) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	return strings.TrimRight(line, "\r\n"), true
}

func TestPlugin_USER_Rejected(t *testing.T) {
	var commands []string
	addr, cleanup := mockPOP3Server(t, func(conn net.Conn, reader *bufio.Reader) {
		pop3Send(conn, "+OK POP3 server ready\r\n")
		if cmd, ok := pop3Recv(reader); ok { // USER
			commands = append(commands, cmd)
		}
		pop3Send(conn, "-ERR no such mailbox\r\n")
		if cmd, ok := pop3Recv(reader); ok { // would be PASS, if sent
			commands = append(commands, cmd)
		}
	})

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "blocked", "hunter2", 5*time.Second, brutus.PluginConfig{})
	cleanup() // synchronize with server goroutine before inspecting commands

	assert.False(t, result.Success)
	assert.Nil(t, result.Error)
	require.Len(t, commands, 1, "PASS must not be sent after USER is rejected")
	assert.Equal(t, "USER blocked", commands[0])
}

func TestPlugin_USER_UnexpectedResponse(t *testing.T) {
	var commands []string
	addr, cleanup := mockPOP3Server(t, func(conn net.Conn, reader *bufio.Reader) {
		pop3Send(conn, "+OK POP3 server ready\r\n")
		if cmd, ok := pop3Recv(reader); ok { // USER
			commands = append(commands, cmd)
		}
		pop3Send(conn, "500 Syntax error\r\n")
		if cmd, ok := pop3Recv(reader); ok { // would be PASS, if sent
			commands = append(commands, cmd)
		}
	})

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "hunter2", 5*time.Second, brutus.PluginConfig{})
	cleanup()

	assert.False(t, result.Success)
	require.NotNil(t, result.Error)
	require.Len(t, commands, 1, "PASS must not be sent after an unexpected USER response")
	assert.Equal(t, "USER admin", commands[0])
}

func TestPlugin_ValidCredentials(t *testing.T) {
	var commands []string
	addr, cleanup := mockPOP3Server(t, func(conn net.Conn, reader *bufio.Reader) {
		pop3Send(conn, "+OK POP3 server ready\r\n")
		if cmd, ok := pop3Recv(reader); ok { // USER
			commands = append(commands, cmd)
		}
		pop3Send(conn, "+OK\r\n")
		if cmd, ok := pop3Recv(reader); ok { // PASS
			commands = append(commands, cmd)
		}
		pop3Send(conn, "+OK Logged in\r\n")
	})

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "hunter2", 5*time.Second, brutus.PluginConfig{})
	cleanup()

	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	require.Len(t, commands, 2, "both USER and PASS must be sent for the happy path")
	assert.Equal(t, "USER admin", commands[0])
	assert.Equal(t, "PASS hunter2", commands[1])
}

func TestPlugin_InvalidPassword(t *testing.T) {
	var commands []string
	addr, cleanup := mockPOP3Server(t, func(conn net.Conn, reader *bufio.Reader) {
		pop3Send(conn, "+OK POP3 server ready\r\n")
		if cmd, ok := pop3Recv(reader); ok { // USER
			commands = append(commands, cmd)
		}
		pop3Send(conn, "+OK\r\n")
		if cmd, ok := pop3Recv(reader); ok { // PASS
			commands = append(commands, cmd)
		}
		pop3Send(conn, "-ERR Invalid password\r\n")
	})

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "wrongpass", 5*time.Second, brutus.PluginConfig{})
	cleanup()

	assert.False(t, result.Success)
	assert.Nil(t, result.Error)
	require.Len(t, commands, 2, "USER and PASS are both sent on a normal auth failure")
	assert.Equal(t, "USER admin", commands[0])
	assert.Equal(t, "PASS wrongpass", commands[1])
}
