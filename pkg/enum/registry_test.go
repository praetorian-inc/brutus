// pkg/enum/registry_test.go
package enum

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPlugin is a minimal Plugin for testing.
type testPlugin struct{ name string }

func (p *testPlugin) Name() string { return p.name }
func (p *testPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	return &Result{Service: p.name, Email: email, Exists: false}
}

func TestRegister_And_GetPlugin(t *testing.T) {
	ResetPlugins()
	Register("test-svc", func() Plugin { return &testPlugin{name: "test-svc"} })

	plug, err := GetPlugin("test-svc")
	require.NoError(t, err)
	assert.Equal(t, "test-svc", plug.Name())
}

func TestGetPlugin_Unknown(t *testing.T) {
	ResetPlugins()
	_, err := GetPlugin("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestGetPlugin_FreshInstances(t *testing.T) {
	ResetPlugins()
	Register("fresh", func() Plugin { return &testPlugin{name: "fresh"} })

	p1, _ := GetPlugin("fresh")
	p2, _ := GetPlugin("fresh")
	assert.NotSame(t, p1, p2, "each call should return a new instance")
}

func TestListPlugins_Sorted(t *testing.T) {
	ResetPlugins()
	Register("zebra", func() Plugin { return &testPlugin{name: "zebra"} })
	Register("alpha", func() Plugin { return &testPlugin{name: "alpha"} })

	names := ListPlugins()
	assert.Equal(t, []string{"alpha", "zebra"}, names)
}

func TestRegister_Duplicate_Panics(t *testing.T) {
	ResetPlugins()
	Register("dup", func() Plugin { return &testPlugin{name: "dup"} })

	assert.Panics(t, func() {
		Register("dup", func() Plugin { return &testPlugin{name: "dup"} })
	})
}

func TestResetPlugins(t *testing.T) {
	ResetPlugins()
	Register("temp", func() Plugin { return &testPlugin{name: "temp"} })
	assert.Len(t, ListPlugins(), 1)

	ResetPlugins()
	assert.Len(t, ListPlugins(), 0)
}
