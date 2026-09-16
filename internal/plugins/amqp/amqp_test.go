package amqp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func startStallingServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start stalling server: %v", err)
	}

	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "amqp", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "guest", "guest", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("ACCESS-REFUSED")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}

func TestPlugin_Test_StalledHandshakeDoesNotHang(t *testing.T) {
	plugin := &Plugin{}
	target := startStallingServer(t)

	done := make(chan struct{})
	var result *brutus.Result
	go func() {
		result = plugin.Test(context.Background(), target, "guest", "guest", 500*time.Millisecond, brutus.PluginConfig{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Test() did not return within 5s - handshake deadline missing (regressed)")
	}

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Error(t, result.Error)
}
