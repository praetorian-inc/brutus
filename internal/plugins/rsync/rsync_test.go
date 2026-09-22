package rsync

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
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

func TestPlugin_Test_ValidPassword(t *testing.T) {
	addr := mockRsyncAuth(t, "mod", "secret")
	r := (&Plugin{}).Test(context.Background(), addr, "mod", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_Test_InvalidPassword(t *testing.T) {
	addr := mockRsyncAuth(t, "mod", "secret")
	r := (&Plugin{}).Test(context.Background(), addr, "mod", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "AUTHREQD rejection must classify as auth failure")
}

func mockRsyncAuth(t *testing.T, module, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	const challenge = "abc123"
	want := md5.Sum([]byte(password + challenge))
	wantHex := hex.EncodeToString(want[:])
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, "@RSYNCD: 31.0\n")
		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n') // client version
		_, _ = r.ReadString('\n') // module
		_, _ = fmt.Fprintf(conn, "@RSYNCD: AUTHREQD %s\n", challenge)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) == 2 && parts[0] == module && parts[1] == wantHex {
			_, _ = io.WriteString(conn, "@RSYNCD: OK\n")
			return
		}
		_, _ = io.WriteString(conn, "@RSYNCD: ERROR\n")
	}()
	return ln.Addr().String()
}
