package rsync

import (
	"bufio"
	"context"
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
	assert.Equal(t, "rsync", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "mod", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_CheckUnauth_Open(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "@RSYNCD: 31.0\n")
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = io.WriteString(conn, "@RSYNCD: OK\n")
	}()
	r := (&Plugin{}).CheckUnauth(context.Background(), ln.Addr().String(), 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
}

func TestPlugin_CheckUnauth_ClosedPort(t *testing.T) {
	r := (&Plugin{}).CheckUnauth(context.Background(), "127.0.0.1:1", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func TestPlugin_Test_AuthRequiredSuccess(t *testing.T) {
	addr, cleanup := mockRsync(t, func(conn net.Conn, reader *bufio.Reader) {
		_, _ = io.WriteString(conn, "@RSYNCD: 31.0\n")
		_, _ = reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "@RSYNCD: AUTHREQD deadbeef\n")
		line, _ := reader.ReadString('\n')
		assert.True(t, strings.HasPrefix(line, "public "))
		_, _ = io.WriteString(conn, "@RSYNCD: OK\n")
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "public", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_Test_AuthRequiredFailure(t *testing.T) {
	addr, cleanup := mockRsync(t, func(conn net.Conn, reader *bufio.Reader) {
		_, _ = io.WriteString(conn, "@RSYNCD: 31.0\n")
		_, _ = reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "@RSYNCD: AUTHREQD deadbeef\n")
		_, _ = reader.ReadString('\n')
		_, _ = io.WriteString(conn, "@ERROR: auth failed\n")
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "public", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_Test_UnexpectedGreeting(t *testing.T) {
	addr, cleanup := mockRsync(t, func(conn net.Conn, _ *bufio.Reader) {
		_, _ = io.WriteString(conn, "SSH-2.0-OpenSSH\n")
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "public", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func mockRsync(t *testing.T, handler func(conn net.Conn, reader *bufio.Reader)) (addr string, cleanup func()) {
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
		handler(conn, bufio.NewReader(conn))
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}
