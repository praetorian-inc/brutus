package activemq

import (
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
	assert.Equal(t, "activemq", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "admin", "admin", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "activemq", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:61616", "admin", "admin", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "admin", "admin", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "invalid user or password", errStr: "User name or password is invalid", wantAuth: true},
		{name: "authentication", errStr: "authentication failed", wantAuth: true},
		{name: "unauthorized", errStr: "unauthorized", wantAuth: true},
		{name: "invalid user", errStr: "invalid user", wantAuth: true},
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

func TestPlugin_Test_UnbracketedIPv6(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "::1", "admin", "admin", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:61616", "admin", "admin", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("activemq")
	require.NoError(t, err)
	assert.Equal(t, "activemq", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr := mockOpenWire(t, []byte("ConnectionInfo"))
	r := (&Plugin{}).Test(context.Background(), addr, "admin", "admin", 3*time.Second, brutus.PluginConfig{})
	require.Nil(t, r.Error)
	assert.True(t, r.Success)
	assert.Equal(t, "activemq", r.Protocol)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr := mockOpenWire(t, []byte("Exception: User name or password is invalid"))
	r := (&Plugin{}).Test(context.Background(), addr, "admin", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "auth failure must not be a connection error")
}

func mockOpenWire(t *testing.T, connInfoReply []byte) string {
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
		if _, err := readFrame(conn); err != nil {
			return
		}
		if err := writeFrame(conn, []byte{1}); err != nil {
			return
		}
		if _, err := readFrame(conn); err != nil {
			return
		}
		_ = writeFrame(conn, connInfoReply)
	}()
	return ln.Addr().String()
}

func TestReadFrame_TooLarge(t *testing.T) {
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()
	go func() {
		_, _ = w.Write([]byte{0x00, 0x20, 0x00, 0x01}) // 2MiB+1
		_ = w.Close()
	}()
	_, err := readFrame(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestReadFrame_RoundTrip(t *testing.T) {
	r, w := net.Pipe()
	defer func() { _ = r.Close(); _ = w.Close() }()
	go func() {
		_ = writeFrame(w, []byte("hello"))
	}()
	got, err := readFrame(r)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
}
