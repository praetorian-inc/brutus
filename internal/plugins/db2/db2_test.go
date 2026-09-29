package db2

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
	assert.Equal(t, "db2", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "db2inst1", "db2inst1", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "db2", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:50000", "db2inst1", "db2inst1", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "db2inst1", "db2inst1", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "SQL30082N", errStr: "SQL30082N", wantAuth: true},
		{name: "sql30082", errStr: "sql30082", wantAuth: true},
		{name: "password invalid", errStr: "password invalid", wantAuth: true},
		{name: "security mechanism", errStr: "security mechanism not supported", wantAuth: true},
		{name: "userid is invalid", errStr: "userid is invalid", wantAuth: true},
		{name: "authentication", errStr: "authentication failed", wantAuth: true},
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
	r := (&Plugin{}).Test(context.Background(), "::1", "db2inst1", "db2inst1", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("db2")
	require.NoError(t, err)
	assert.Equal(t, "db2", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr := mockDRDA(t, ddm(0x1219, []byte{0x00, 0x00, 0x00, 0x00}))
	r := (&Plugin{}).Test(context.Background(), addr, "db2inst1", "db2inst1", 3*time.Second, brutus.PluginConfig{})
	require.Nil(t, r.Error)
	assert.True(t, r.Success)
	assert.Equal(t, "db2", r.Protocol)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr := mockDRDA(t, ddm(0x1219, []byte("SQL30082N password invalid")))
	r := (&Plugin{}).Test(context.Background(), addr, "db2inst1", "wrong", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error, "SQL30082 must be an auth failure, not a connection error")
}

func mockDRDA(t *testing.T, secchk []byte) string {
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
		ack := ddm(0x1443, []byte{0x00, 0x01})
		if _, err := readDSS(conn); err != nil {
			return
		}
		if err := writeDSS(conn, ack); err != nil {
			return
		}
		if _, err := readDSS(conn); err != nil {
			return
		}
		if err := writeDSS(conn, ack); err != nil {
			return
		}
		if _, err := readDSS(conn); err != nil {
			return
		}
		_ = writeDSS(conn, secchk)
	}()
	return ln.Addr().String()
}
