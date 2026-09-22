package firebird

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
	assert.Equal(t, "firebird", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "sysdba", "masterkey", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "firebird", r.Protocol)
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
		{name: "user name and password not defined", errStr: "Your user name and password are not defined", wantAuth: true},
		{name: "login", errStr: "login failed", wantAuth: true},
		{name: "password", errStr: "password", wantAuth: true},
		{name: "sqlcode -902", errStr: "SQLCODE = -902", wantAuth: true},
		{name: "authentication error", errStr: "authentication error", wantAuth: true},
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
	r := (&Plugin{}).Test(context.Background(), "::1", "sysdba", "masterkey", 200*time.Millisecond, brutus.PluginConfig{})
	assert.NotNil(t, r)
	if r.Error != nil {
		assert.NotContains(t, r.Error.Error(), "too many colons")
	}
}

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("firebird")
	require.NoError(t, err)
	assert.Equal(t, "firebird", p.Name())
}
