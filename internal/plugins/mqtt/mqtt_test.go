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

package mqtt

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "mqtt", p.Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	result := p.Test(context.Background(), "127.0.0.1:1", "user", "pass", 2*time.Second, brutus.PluginConfig{})
	assert.NotNil(t, result)
	assert.Equal(t, "mqtt", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, codeAccepted)
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "admin", 5*time.Second, brutus.PluginConfig{})
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, codeBadUserOrPass)
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "wrong", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.Nil(t, result.Error, "auth failure should not return error")
}

func TestPlugin_Test_NotAuthorized(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, codeNotAuthorized)
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "admin", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_Test_ServerUnavailable(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, 3)
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "admin", 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_CheckUnauth_Open(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, codeAccepted)
	defer cleanup()

	p := &Plugin{}
	result := p.CheckUnauth(context.Background(), addr, 5*time.Second, brutus.PluginConfig{})
	assert.True(t, result.Success)
	assert.Contains(t, result.Banner, "without authentication")
}

func TestPlugin_CheckUnauth_RequiresAuth(t *testing.T) {
	addr, cleanup := mockMQTTServer(t, codeNotAuthorized)
	defer cleanup()

	p := &Plugin{}
	result := p.CheckUnauth(context.Background(), addr, 5*time.Second, brutus.PluginConfig{})
	assert.False(t, result.Success)
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "not authorized", errStr: "not authorized", wantAuth: true},
		{name: "bad username", errStr: "bad user name or password", wantAuth: true},
		{name: "connack 4", errStr: "mqtt connack 4", wantAuth: true},
		{name: "connack 5", errStr: "mqtt connack 5", wantAuth: true},
		{name: "connection refused", errStr: "connection refused", wantAuth: false},
		{name: "timeout", errStr: "context deadline exceeded", wantAuth: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyError(errors.New(tt.errStr))
			if tt.wantAuth {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestEncodeConnect_HasUsernamePassword(t *testing.T) {
	pkt := encodeConnect("user", "pass")
	assert.Equal(t, byte(packetConnect), pkt[0])
	assert.Contains(t, string(pkt), "MQTT")
	assert.Contains(t, string(pkt), "user")
	assert.Contains(t, string(pkt), "pass")
}

func TestEncodeConnect_Anonymous(t *testing.T) {
	pkt := encodeConnect("", "")
	assert.Equal(t, byte(packetConnect), pkt[0])
	assert.NotContains(t, string(pkt), "user")
}

func TestReadConnack_WrongPacket(t *testing.T) {
	_, err := readConnack(bytes.NewReader([]byte{0x30, 0x02, 0x00, 0x00}))
	assert.Error(t, err)
}

func mockMQTTServer(t *testing.T, returnCode byte) (addr string, cleanup func()) {
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
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{packetConnack, 0x02, 0x00, returnCode})
	}()

	cleanup = func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), cleanup
}
