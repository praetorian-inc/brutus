package mqtt

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
	assert.Equal(t, "mqtt", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_ValidAndInvalid(t *testing.T) {
	addr, cleanup := mockMQTT(t, codeAccepted)
	defer cleanup()
	r := (&Plugin{}).Test(context.Background(), addr, "admin", "admin", 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)

	addr, cleanup = mockMQTT(t, codeBadUserPass)
	defer cleanup()
	r = (&Plugin{}).Test(context.Background(), addr, "admin", "bad", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("not authorized")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}

func mockMQTT(t *testing.T, code byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{packetConnack, 0x02, 0x00, code})
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}
