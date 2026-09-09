package brutus_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestBuildTLSConfig(t *testing.T) {
	tests := []struct {
		mode     string
		wantNil  bool
		wantSkip bool
	}{
		{mode: "verify", wantSkip: false},
		{mode: "skip-verify", wantSkip: true},
		{mode: "disable", wantNil: true},
		{mode: "", wantNil: true},
		{mode: "skip", wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := brutus.BuildTLSConfig(tt.mode)
			if tt.wantNil {
				assert.Nil(t, cfg)
				return
			}
			require.NotNil(t, cfg)
			assert.Equal(t, tt.wantSkip, cfg.InsecureSkipVerify)
		})
	}
}

func TestSchemeFromTLSMode(t *testing.T) {
	assert.Equal(t, "https", brutus.SchemeFromTLSMode("verify"))
	assert.Equal(t, "https", brutus.SchemeFromTLSMode("skip-verify"))
	assert.Equal(t, "http", brutus.SchemeFromTLSMode("disable"))
	assert.Equal(t, "http", brutus.SchemeFromTLSMode(""))
	assert.Equal(t, "http", brutus.SchemeFromTLSMode("skip"))
}
