package zookeeper

import (
	"context"
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
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "Environment:\nzookeeper.version=3.8\n")
	}()
	r := (&Plugin{}).CheckUnauth(context.Background(), ln.Addr().String(), 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
}

func TestZkDigest(t *testing.T) {
	assert.NotEmpty(t, zkDigest("user", "pass"))
}
