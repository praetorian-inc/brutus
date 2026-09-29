package amqp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "amqp", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "guest", "guest", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "amqp", r.Protocol)
	assert.Equal(t, "127.0.0.1:1", r.Target)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, r.Duration, time.Duration(0))
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "access-refused", errStr: "ACCESS-REFUSED", wantAuth: true},
		{name: "access refused", errStr: "access refused for user", wantAuth: true},
		{name: "403", errStr: "403", wantAuth: true},
		{name: "authentication failed", errStr: "authentication failed", wantAuth: true},
		{name: "login refused", errStr: "login refused", wantAuth: true},
		{name: "invalid credentials", errStr: "invalid credentials", wantAuth: true},
		{name: "connection refused", errStr: "connection refused", wantAuth: false},
		{name: "no route to host", errStr: "no route to host", wantAuth: false},
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

func TestPlugin_Test_UnbracketedIPv6(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "::1", "guest", "guest", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:5672", "guest", "guest", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("amqp")
	require.NoError(t, err)
	assert.Equal(t, "amqp", p.Name())
}
