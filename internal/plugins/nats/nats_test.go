package nats

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
	assert.Equal(t, "nats", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_AuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "INFO {\"auth_required\":true}\r\n")
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "-ERR 'Authorization Violation'\r\n")
	}()
	r := (&Plugin{}).Test(context.Background(), ln.Addr().String(), "u", "bad", 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("Authorization Violation")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}
