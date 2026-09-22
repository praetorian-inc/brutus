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
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("SQL30082N")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
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
