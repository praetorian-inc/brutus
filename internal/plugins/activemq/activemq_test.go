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
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("User name or password is invalid")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
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
