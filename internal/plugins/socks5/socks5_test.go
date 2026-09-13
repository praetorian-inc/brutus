package socks5

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
	assert.Equal(t, "socks5", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_ValidAndInvalid(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		_, _ = io.ReadFull(conn, buf[:3])
		_, _ = conn.Write([]byte{0x05, 0x02})
		n, _ := conn.Read(buf)
		if n >= 2 && buf[0] == 0x01 {
			_, _ = conn.Write([]byte{0x01, 0x00})
		}
	}()
	r := (&Plugin{}).Test(context.Background(), ln.Addr().String(), "user", "pass", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}
