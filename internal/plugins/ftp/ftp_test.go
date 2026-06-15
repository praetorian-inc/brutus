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

package ftp

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
	assert.Equal(t, "ftp", p.Name())
}

func TestClassifyError(t *testing.T) {
	err := errors.New("dial tcp 10.0.0.1:21: connection refused")
	result := brutus.WrapConnError(err)

	assert.NotNil(t, result)
	assert.Contains(t, result.Error(), "connection error")
	assert.Contains(t, result.Error(), "connection refused")
}

func TestReadFTPResponse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "single-line response",
			input: "220 Ready\r\n",
			want:  "220 Ready",
		},
		{
			name:  "multi-line response",
			input: "220-Welcome to FTP\r\n220-Please read the terms\r\n220 Ready\r\n",
			want:  "220 Ready",
		},
		{
			name:  "code only",
			input: "220\r\n",
			want:  "220",
		},
		{
			name:  "multi-line with code-only final",
			input: "220-Banner line\r\n220\r\n",
			want:  "220",
		},
		{
			name:    "empty input EOF",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			got, err := readFTPResponse(reader)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// mockFTPServer starts a TCP listener that speaks a scripted FTP conversation.
// handler receives the server-side conn and runs the FTP dialog.
func mockFTPServer(t *testing.T, handler func(conn net.Conn)) (addr string, cleanup func()) {
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
		handler(conn)
	}()

	cleanup = func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), cleanup
}

// ftpSend writes an FTP response line to the connection.
func ftpSend(conn net.Conn, msg string) {
	_, _ = fmt.Fprint(conn, msg)
}

// ftpRecv reads one line from the connection (consumes a client command).
func ftpRecv(reader *bufio.Reader) {
	_, _ = reader.ReadString('\n')
}

func TestPlugin_SingleLineBanner_Success(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "331 Password required\r\n")
		ftpRecv(reader) // PASS
		ftpSend(conn, "230 Login successful\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "admin", 5*time.Second, brutus.PluginConfig{})
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_MultiLineBanner_Success(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220-Welcome to FTP\r\n220-Please read our policy\r\n220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "331 Password required\r\n")
		ftpRecv(reader) // PASS
		ftpSend(conn, "230 Login successful\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "admin", 5*time.Second, brutus.PluginConfig{})
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_MultiLineBanner_AuthFailure(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220-Welcome\r\n220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "331 Password required\r\n")
		ftpRecv(reader) // PASS
		ftpSend(conn, "530 Login incorrect\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "wrong", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.Nil(t, result.Error, "auth failure should not return error")
}

func TestPlugin_Anonymous_230_After_USER(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "230 Anonymous login ok\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "anonymous", "", 5*time.Second, brutus.PluginConfig{})
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_USER_Rejected_530(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "530 User not allowed\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "blocked", "pass", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.Nil(t, result.Error, "530 after USER is auth failure, not connection error")
}

func TestPlugin_USER_UnexpectedResponse(t *testing.T) {
	addr, cleanup := mockFTPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		ftpSend(conn, "220 Ready\r\n")
		ftpRecv(reader) // USER
		ftpSend(conn, "500 Syntax error\r\n")
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected FTP response to USER")
}

func TestClassifyAuthError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantNil bool // true = auth failure (return nil), false = connection error (return error)
	}{
		{
			name:    "auth failure - 530 Login incorrect",
			err:     errors.New("530 Login incorrect"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 User cannot log in",
			err:     errors.New("530 User cannot log in"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 Authentication failed",
			err:     errors.New("530 Authentication failed"),
			wantNil: true,
		},
		{
			name:    "auth failure - 530 with mixed case",
			err:     errors.New("530 Not logged in"),
			wantNil: true,
		},
		{
			name:    "connection error - timeout",
			err:     errors.New("dial tcp 10.0.0.1:21: i/o timeout"),
			wantNil: false,
		},
		{
			name:    "connection error - connection refused",
			err:     errors.New("dial tcp 10.0.0.1:21: connection refused"),
			wantNil: false,
		},
		{
			name:    "connection error - network unreachable",
			err:     errors.New("dial tcp 10.0.0.1:21: network is unreachable"),
			wantNil: false,
		},
		{
			name:    "connection error - EOF",
			err:     errors.New("EOF"),
			wantNil: false,
		},
		{
			name:    "connection error - read error",
			err:     errors.New("read tcp 10.0.0.1:21: connection reset by peer"),
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
