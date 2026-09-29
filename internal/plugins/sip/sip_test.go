package sip

import (
	"bufio"
	"context"
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
	assert.Equal(t, "sip", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "1000", "1000", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestDigestResponse(t *testing.T) {
	got := digestResponse("user", "pass", "REGISTER", "sip:host", map[string]string{"realm": "r", "nonce": "n"})
	assert.Len(t, got, 32)
	assert.Equal(t, digestResponse("user", "pass", "REGISTER", "sip:host", map[string]string{"realm": "r", "nonce": "n"}), got)
	assert.NotEqual(t, got, digestResponse("user", "wrong", "REGISTER", "sip:host", map[string]string{"realm": "r", "nonce": "n"}))
}

func TestParseAuth(t *testing.T) {
	got := parseAuth(`Digest realm="asterisk", nonce="abc123", algorithm=MD5, opaque="xyz"`)
	assert.Equal(t, "asterisk", got["realm"])
	assert.Equal(t, "abc123", got["nonce"])
	assert.Equal(t, "MD5", got["algorithm"])
	assert.Equal(t, "xyz", got["opaque"])
}

func TestRegisterRequest(t *testing.T) {
	req := registerRequest("sip.test", "5060", "1000", "callid", "z9hG4bKbranch", 1, "")
	assert.Contains(t, req, "REGISTER sip:sip.test SIP/2.0")
	assert.Contains(t, req, "CSeq: 1 REGISTER")
	assert.NotContains(t, req, "Authorization:")

	authed := registerRequest("sip.test", "5061", "1000", "callid", "z9hG4bKbranch", 2, `Digest username="1000"`)
	assert.Contains(t, authed, "REGISTER sip:sip.test:5061 SIP/2.0")
	assert.Contains(t, authed, "Authorization: Digest username=\"1000\"")
}

func TestPlugin_DigestSuccess(t *testing.T) {
	addr, cleanup := mockSIPServer(t, func(conn net.Conn) {
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 401, map[string]string{
			"WWW-Authenticate": `Digest realm="asterisk", nonce="abc123", algorithm=MD5`,
		})
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 200, nil)
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "1000", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_DigestAuthFailure(t *testing.T) {
	addr, cleanup := mockSIPServer(t, func(conn net.Conn) {
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 401, map[string]string{
			"WWW-Authenticate": `Digest realm="asterisk", nonce="abc123", algorithm=MD5`,
		})
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 403, nil)
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "1000", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_UnexpectedStatus(t *testing.T) {
	addr, cleanup := mockSIPServer(t, func(conn net.Conn) {
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 500, nil)
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "1000", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_UnauthenticatedOK(t *testing.T) {
	addr, cleanup := mockSIPServer(t, func(conn net.Conn) {
		require.NoError(t, readSIPRequest(conn))
		writeSIP(conn, 200, nil)
	})
	defer cleanup()

	r := (&Plugin{}).Test(context.Background(), addr, "1000", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func mockSIPServer(t *testing.T, handler func(conn net.Conn)) (addr string, cleanup func()) {
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

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func readSIPRequest(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			return nil
		}
	}
}

func writeSIP(conn net.Conn, status int, headers map[string]string) {
	reason := "OK"
	if status != 200 {
		reason = "Error"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", status, reason)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	_, _ = io.WriteString(conn, b.String())
}
