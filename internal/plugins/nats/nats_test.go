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
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("Authorization Violation")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
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
