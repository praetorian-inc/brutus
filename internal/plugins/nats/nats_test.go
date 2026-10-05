package nats

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "nats", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "nats", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:4222", "u", "p", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "u", "p", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "authorization violation", errStr: "Authorization Violation", wantAuth: true},
		{name: "authentication", errStr: "authentication required", wantAuth: true},
		{name: "auth required", errStr: "auth required", wantAuth: true},
		{name: "nats authorization", errStr: "nats: authorization", wantAuth: true},
		{name: "connection refused", errStr: "connection refused", wantAuth: false},
		{name: "no route to host", errStr: "no route to host", wantAuth: false},
		{name: "deadline exceeded", errStr: "context deadline exceeded", wantAuth: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(errors.New(tt.errStr))
			if tt.wantAuth {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Contains(t, got.Error(), "connection error")
		})
	}
}

func TestPlugin_CheckUnauth_ClosedPort(t *testing.T) {
	r := (&Plugin{}).CheckUnauth(context.Background(), "127.0.0.1:1", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Equal(t, "(unauthenticated)", r.Username)
}

func TestPlugin_Test_UnbracketedIPv6(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "::1", "u", "p", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("nats")
	require.NoError(t, err)
	assert.Equal(t, "nats", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr := mockNATS(t, true)
	r := (&Plugin{}).Test(context.Background(), addr, "user", "pass", 3*time.Second, brutus.PluginConfig{})
	require.Nil(t, r.Error)
	assert.True(t, r.Success)
	assert.Equal(t, "nats", r.Protocol)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr := mockNATS(t, false)
	r := (&Plugin{}).Test(context.Background(), addr, "user", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "Authorization Violation must classify as auth failure")
}

func TestPlugin_CheckUnauth_Open(t *testing.T) {
	addr := mockNATS(t, true)
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Contains(t, r.Banner, "[CRITICAL]")
}

func TestPlugin_CheckUnauth_AuthRequired(t *testing.T) {
	addr := mockNATS(t, false)
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func mockNATS(t *testing.T, accept bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		info := "INFO {\"server_id\":\"test\",\"version\":\"2.10.0\",\"go\":\"go1.22\",\"host\":\"127.0.0.1\",\"port\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"proto\":1,\"client_id\":1}\r\n"
		if _, err := io.WriteString(conn, info); err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "CONNECT"):
				if !accept {
					_, _ = io.WriteString(conn, "-ERR 'Authorization Violation'\r\n")
					return
				}
			case strings.HasPrefix(line, "PING"):
				_, _ = io.WriteString(conn, "PONG\r\n")
			}
		}
	}()
	return ln.Addr().String()
}
