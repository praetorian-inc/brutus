package memcached

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "memcached", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
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
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "VERSION 1.6.0\r\n")
	}()
	r := (&Plugin{}).CheckUnauth(context.Background(), ln.Addr().String(), 3*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
}

func TestPlugin_Test_SASL(t *testing.T) {
	tests := []struct {
		name    string
		hdr     []byte
		success bool
		errSub  string
	}{
		{
			name:    "success",
			hdr:     saslHeader(magicRes, opcodeSASLAuth, statusSuccess, 0),
			success: true,
		},
		{
			name:   "auth error",
			hdr:    saslHeader(magicRes, opcodeSASLAuth, statusAuthErr, 0),
			errSub: "",
		},
		{
			name:   "wrong magic",
			hdr:    saslHeader(0x00, opcodeSASLAuth, statusSuccess, 0),
			errSub: "unexpected memcached header",
		},
		{
			name:   "wrong opcode",
			hdr:    saslHeader(magicRes, 0x00, statusSuccess, 0),
			errSub: "unexpected memcached header",
		},
		{
			name:   "other status",
			hdr:    saslHeader(magicRes, opcodeSASLAuth, 0x0001, 0),
			errSub: "memcached status 0x0001",
		},
		{
			name:   "truncated",
			hdr:    []byte{magicRes, opcodeSASLAuth},
			errSub: "connection error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := serveOnce(t, tt.hdr)
			r := (&Plugin{}).Test(context.Background(), addr, "user", "pass", 3*time.Second, brutus.PluginConfig{})
			assert.Equal(t, tt.success, r.Success)
			if tt.errSub == "" {
				assert.Nil(t, r.Error)
			} else {
				require.NotNil(t, r.Error)
				assert.Contains(t, r.Error.Error(), tt.errSub)
			}
		})
	}
}

func saslHeader(magic, opcode byte, status uint16, bodyLen uint32) []byte {
	hdr := make([]byte, 24)
	hdr[0] = magic
	hdr[1] = opcode
	binary.BigEndian.PutUint16(hdr[6:8], status)
	binary.BigEndian.PutUint32(hdr[8:12], bodyLen)
	return hdr
}

func serveOnce(t *testing.T, resp []byte) string {
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
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(resp)
	}()
	return ln.Addr().String()
}
