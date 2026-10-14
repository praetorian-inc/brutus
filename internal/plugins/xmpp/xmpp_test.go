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
	assert.Equal(t, "xmpp", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "not-authorized", errStr: "not-authorized", wantAuth: true},
		{name: "authentication failed", errStr: "authentication failed", wantAuth: true},
		{name: "invalid-authzid", errStr: "invalid-authzid", wantAuth: true},
		{name: "sasl", errStr: "sasl failure", wantAuth: true},
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
	r := (&Plugin{}).Test(context.Background(), "::1", "u", "p", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:5222", "u", "p", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("xmpp")
	require.NoError(t, err)
	assert.Equal(t, "xmpp", p.Name())
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
