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
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("not authorized")))
	assert.NotNil(t, classifyError(errors.New("i/o timeout")))
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
