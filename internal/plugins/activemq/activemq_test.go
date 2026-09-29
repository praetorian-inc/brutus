package activemq

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
	assert.Equal(t, "activemq", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "admin", "admin", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "activemq", r.Protocol)
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "invalid user or password", errStr: "User name or password is invalid", wantAuth: true},
		{name: "authentication", errStr: "authentication failed", wantAuth: true},
		{name: "unauthorized", errStr: "unauthorized", wantAuth: true},
		{name: "invalid user", errStr: "invalid user", wantAuth: true},
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
	r := (&Plugin{}).Test(context.Background(), "::1", "admin", "admin", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:61616", "admin", "admin", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})
	assert.False(t, r.Success)
	require.NotNil(t, r.Error)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("activemq")
	require.NoError(t, err)
	assert.Equal(t, "activemq", p.Name())
}
