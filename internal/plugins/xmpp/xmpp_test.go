package xmpp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "xmpp", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("not-authorized")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr := mockXMPP(t, `<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>`)
	r := (&Plugin{}).Test(context.Background(), addr, "alice", "secret", 3*time.Second, brutus.PluginConfig{})
	require.Nil(t, r.Error)
	assert.True(t, r.Success)
	assert.Equal(t, "xmpp", r.Protocol)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr := mockXMPP(t, `<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>`)
	r := (&Plugin{}).Test(context.Background(), addr, "alice", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "not-authorized must be an auth failure, not a connection error")
}

func TestPlugin_Test_UnexpectedResponse(t *testing.T) {
	addr := mockXMPP(t, `<stream:error><internal-server-error/></stream:error>`)
	r := (&Plugin{}).Test(context.Background(), addr, "alice", "secret", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	require.Error(t, r.Error)
	assert.Contains(t, r.Error.Error(), "unexpected xmpp response")
}

func mockXMPP(t *testing.T, authReply string) string {
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
		r := bufio.NewReader(conn)
		buf := make([]byte, 4096)
		if _, err := r.Read(buf); err != nil && err != io.EOF {
			return
		}
		_, _ = io.WriteString(conn, `<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>`)
		if _, err := r.Read(buf); err != nil && err != io.EOF {
			return
		}
		_, _ = io.WriteString(conn, authReply)
	}()
	return ln.Addr().String()
}
