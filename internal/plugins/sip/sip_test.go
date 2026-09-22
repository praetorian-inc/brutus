package sip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "sip", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "1000", "1000", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_DigestSuccess(t *testing.T) {
	addr := mockSIPDigest(t, 200)
	r := (&Plugin{}).Test(context.Background(), addr, "1000", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_Test_DigestRejected(t *testing.T) {
	addr := mockSIPDigest(t, 403)
	r := (&Plugin{}).Test(context.Background(), addr, "1000", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "403 after digest must classify as auth failure")
}

func TestPlugin_Test_OpenRegister(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		drainSIP(bufio.NewReader(conn))
		_, _ = io.WriteString(conn, "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	}()
	r := (&Plugin{}).Test(context.Background(), ln.Addr().String(), "1000", "x", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
}

func mockSIPDigest(t *testing.T, secondStatus int) string {
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
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		drainSIP(r)
		_, _ = io.WriteString(conn, "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"asterisk\", nonce=\"abc\"\r\nContent-Length: 0\r\n\r\n")
		drainSIP(r)
		_, _ = fmt.Fprintf(conn, "SIP/2.0 %d Forbidden\r\nContent-Length: 0\r\n\r\n", secondStatus)
	}()
	return ln.Addr().String()
}

func drainSIP(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			return
		}
	}
}

func TestDigestResponse(t *testing.T) {
	got := digestResponse("user", "pass", "REGISTER", "sip:host", map[string]string{"realm": "r", "nonce": "n"})
	assert.Len(t, got, 32)
}
