package firebird

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "firebird", (&Plugin{}).Name())
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	r := (&Plugin{}).Test(context.Background(), "127.0.0.1:1", "SYSDBA", "masterkey", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Contains(t, r.Error.Error(), "connection error")
}

func TestClassifyError(t *testing.T) {
	assert.Nil(t, classifyError(errors.New("Your user name and password are not defined")))
	assert.NotNil(t, classifyError(errors.New("connection refused")))
}
