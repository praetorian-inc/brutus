package ipmi

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
	assert.Equal(t, "ipmi", (&Plugin{}).Name())
}

func TestPlugin_Test_Unreachable(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "admin", "admin", 2*time.Second, brutus.PluginConfig{})
	assert.Equal(t, "ipmi", r.Protocol)
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
		{name: "unauthorized", errStr: "unauthorized", wantAuth: true},
		{name: "authentication failed", errStr: "authentication failed", wantAuth: true},
		{name: "invalid user", errStr: "invalid user", wantAuth: true},
		{name: "wrong password", errStr: "wrong password", wantAuth: true},
		{name: "privilege", errStr: "privilege violation", wantAuth: true},
		{name: "rakp", errStr: "RAKP HMAC invalid", wantAuth: true},
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

func TestInit(t *testing.T) {
	p, err := brutus.GetPlugin("ipmi")
	require.NoError(t, err)
	assert.Equal(t, "ipmi", p.Name())
}
