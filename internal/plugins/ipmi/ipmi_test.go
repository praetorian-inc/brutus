package ipmi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "ipmi", (&Plugin{}).Name())
}

func TestPlugin_Test_Unreachable(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "ADMIN", "ADMIN", 1*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestChecksum(t *testing.T) {
	assert.Equal(t, byte(0), checksum([]byte{0xff, 0x01}))
}
