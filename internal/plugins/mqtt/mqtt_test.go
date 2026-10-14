package mqtt

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
	assert.Equal(t, "mqtt", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "mqtt", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1883", "u", "p", time.Second,
		brutus.PluginConfig{ProxyURL: "ftp://proxy.example"})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "u", "p", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "not authorized", errStr: "not authorized", wantAuth: true},
		{name: "bad user name or password", errStr: "bad user name or password", wantAuth: true},
		{name: "bad username or password", errStr: "Bad username or password", wantAuth: true},
		{name: "i/o timeout", errStr: "i/o timeout", wantAuth: false},
		{name: "connection refused", errStr: "connection refused", wantAuth: false},
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

func TestPlugin_CheckUnauth_ClosedPort(t *testing.T) {
	r := (&Plugin{}).CheckUnauth(context.Background(), "127.0.0.1:1", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Equal(t, "(unauthenticated)", r.Username)
}

func TestPlugin_Test_UnbracketedIPv6(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "::1", "u", "p", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("mqtt")
	require.NoError(t, err)
	assert.Equal(t, "mqtt", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	addr := mockMQTT(t, 0)
	r := (&Plugin{}).Test(context.Background(), addr, "user", "pass", 3*time.Second, brutus.PluginConfig{})
	require.Nil(t, r.Error)
	assert.True(t, r.Success)
	assert.Equal(t, "mqtt", r.Protocol)
}

func TestPlugin_CheckUnauth_Accepted(t *testing.T) {
	addr := mockMQTT(t, 0)
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Contains(t, r.Banner, "[CRITICAL]")
}

func TestPlugin_CheckUnauth_Rejected(t *testing.T) {
	addr := mockMQTT(t, 5) // not authorized
	r := (&Plugin{}).CheckUnauth(context.Background(), addr, 3*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
}

func mockMQTT(t *testing.T, returnCode byte) string {
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
		_ = readMQTTPacket(conn)
		_, _ = conn.Write([]byte{0x20, 0x02, 0x00, returnCode})
		if returnCode != 0 {
			time.Sleep(20 * time.Millisecond)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

func readMQTTPacket(r io.Reader) error {
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	length, err := readMQTTRemainingLength(r)
	if err != nil {
		return err
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return err
}

func readMQTTRemainingLength(r io.Reader) (int, error) {
	multiplier, value := 1, 0
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		value += int(b[0]&127) * multiplier
		if b[0]&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, errors.New("malformed remaining length")
}
