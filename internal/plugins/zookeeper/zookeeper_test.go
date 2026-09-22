package zookeeper

import (
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
	assert.Equal(t, "zookeeper", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "zk", "zk", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("zk: client authentication failed")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}

func TestPlugin_CheckUnauth_Open(t *testing.T) {
	addr := mockRuok(t, "imok")
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 2*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Contains(t, r.Banner, "CRITICAL")
}

func TestPlugin_CheckUnauth_NotImok(t *testing.T) {
	addr := mockRuok(t, "thisisnotzk")
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func TestPlugin_CheckUnauth_ClosedPort(t *testing.T) {
	r := (&Plugin{}).CheckUnauth(context.Background(), "127.0.0.1:1", 500*time.Millisecond, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func mockRuok(t *testing.T, reply string) string {
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
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = io.WriteString(conn, reply)
	}()
	return ln.Addr().String()
}
