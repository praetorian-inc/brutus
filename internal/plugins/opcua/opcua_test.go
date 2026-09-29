package opcua

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
	assert.Equal(t, "opcua", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "u", "p", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "opcua", r.Protocol)
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
		{name: "BadUserAccessDenied", errStr: "BadUserAccessDenied", wantAuth: true},
		{name: "BadIdentityTokenRejected", errStr: "BadIdentityTokenRejected", wantAuth: true},
		{name: "BadIdentityTokenInvalid", errStr: "BadIdentityTokenInvalid", wantAuth: true},
		{name: "user access denied", errStr: "user access denied", wantAuth: true},
		{name: "StatusBadUserAccessDenied", errStr: "StatusBadUserAccessDenied", wantAuth: true},
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
	p, err := brutus.GetPlugin("opcua")
	require.NoError(t, err)
	assert.Equal(t, "opcua", p.Name())
}
