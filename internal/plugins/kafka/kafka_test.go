package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "kafka", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantNil bool
	}{
		{name: "sasl failed", err: kafkago.SASLAuthenticationFailed, wantNil: true},
		{name: "wrapped sasl failed", err: fmt.Errorf("authenticate: %w", kafkago.SASLAuthenticationFailed), wantNil: true},
		{name: "string sasl", err: errors.New("SASL authentication failed"), wantNil: true},
		{name: "network exception", err: kafkago.NetworkException, wantNil: false},
		{name: "listener not found", err: kafkago.ListenerNotFound, wantNil: false},
		{name: "connection refused", err: errors.New("connection refused"), wantNil: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err)
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Contains(t, got.Error(), "connection error")
			}
		})
	}
}

func TestPlugin_Test_TLSHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		time.Sleep(5 * time.Second)
	}()
	start := time.Now()
	r := (&Plugin{}).Test(context.Background(), ln.Addr().String(), "u", "p", 300*time.Millisecond, brutus.PluginConfig{TLSMode: "skip-verify"})
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}
