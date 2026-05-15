package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestCapability_Interface(t *testing.T) {
	var _ capability.Capability[capmodel.Port] = (*Capability)(nil)
}

func TestCapability_Name(t *testing.T) {
	c := NewCapability()
	assert.Equal(t, "brutus", c.Name())
}

func TestCapability_Description(t *testing.T) {
	c := NewCapability()
	assert.Equal(t, "credential testing against network services", c.Description())
}

func TestCapability_Input(t *testing.T) {
	c := NewCapability()
	assert.Equal(t, capmodel.Port{}, c.Input())
}

func TestCapability_Parameters(t *testing.T) {
	c := NewCapability()
	params := c.Parameters()

	require.Len(t, params, 4)

	assert.Equal(t, "usernames", params[0].Name)
	assert.Equal(t, "string", params[0].Type)

	assert.Equal(t, "passwords", params[1].Name)
	assert.Equal(t, "string", params[1].Type)

	assert.Equal(t, "ratelimit", params[2].Name)
	assert.Equal(t, "float", params[2].Type)

	assert.Equal(t, "protocol", params[3].Name)
	assert.Equal(t, "string", params[3].Type)
}

func TestCapability_Match_ManualOnly(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: true}
	err := c.Match(ctx, capmodel.Port{})
	assert.NoError(t, err)
}

func TestCapability_Match_RejectsAutomated(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: false}
	err := c.Match(ctx, capmodel.Port{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "manually")
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple",
			input:    "admin,root,user",
			expected: []string{"admin", "root", "user"},
		},
		{
			name:     "with spaces",
			input:    " admin , root , user ",
			expected: []string{"admin", "root", "user"},
		},
		{
			name:     "single value",
			input:    "admin",
			expected: []string{"admin"},
		},
		{
			name:     "empty strings filtered",
			input:    "admin,,root,",
			expected: []string{"admin", "root"},
		},
		{
			name:     "all empty",
			input:    ",,",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCapability_Invoke_InvalidPort(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: true}
	input := capmodel.Port{
		Service: "ssh",
		Port:    0,
		Parent:  capmodel.Asset{DNS: "example.com"},
	}
	err := c.Invoke(ctx, input, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

func TestCapability_Invoke_EmptyHostname(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: true}
	input := capmodel.Port{
		Service: "ssh",
		Port:    22,
		Parent:  capmodel.Asset{DNS: ""},
	}
	err := c.Invoke(ctx, input, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no hostname")
}

func TestCapability_Invoke_NoProtocol(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: true}
	input := capmodel.Port{
		Port:   22,
		Parent: capmodel.Asset{DNS: "example.com"},
	}
	err := c.Invoke(ctx, input, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no protocol")
}

// mockPlugin is a test plugin that always succeeds.
type mockPlugin struct{}

func (p *mockPlugin) Name() string { return "mock-test" }
func (p *mockPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	return &brutus.Result{
		Protocol: "mock-test",
		Target:   target,
		Username: username,
		Password: password,
		Success:  true,
		Banner:   "mock banner",
	}
}

func TestCapability_Invoke_Success(t *testing.T) {
	brutus.ResetPlugins()
	brutus.Register("mock-test", func() brutus.Plugin { return &mockPlugin{} })
	defer brutus.ResetPlugins()

	c := NewCapability()

	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "password123", Type: "string"},
			{Name: "protocol", Value: "mock-test", Type: "string"},
		},
	}

	input := capmodel.Port{
		Port:    22,
		Service: "mock-test",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	err := c.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	risk, ok := emitted[0].(capmodel.Risk)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1:22", risk.TargetName)
	assert.Equal(t, "Weak Credentials", risk.Name)
	assert.Equal(t, "brutus", risk.Source)
	assert.Equal(t, "OH", risk.Status)

	var proof map[string]string
	err = json.Unmarshal(risk.Proof, &proof)
	require.NoError(t, err)
	assert.Equal(t, "admin", proof["username"])
	assert.Equal(t, "password123", proof["password"])
	assert.Equal(t, "mock-test", proof["protocol"])
}

type mockFailPlugin struct{}

func (p *mockFailPlugin) Name() string { return "mock-fail" }
func (p *mockFailPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	return &brutus.Result{
		Protocol: "mock-fail",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}
}

func TestCapability_Invoke_NoSuccessfulResults(t *testing.T) {
	brutus.ResetPlugins()
	brutus.Register("mock-fail", func() brutus.Plugin { return &mockFailPlugin{} })
	defer brutus.ResetPlugins()

	c := NewCapability()

	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "wrong", Type: "string"},
			{Name: "protocol", Value: "mock-fail", Type: "string"},
		},
	}

	input := capmodel.Port{
		Port:    22,
		Service: "mock-fail",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	err := c.Invoke(ctx, input, emitter)
	assert.NoError(t, err)
	assert.Empty(t, emitted, "no risks should be emitted for failed auth")
}

func TestCapability_Invoke_ProtocolFromService(t *testing.T) {
	brutus.ResetPlugins()
	brutus.Register("mock-test", func() brutus.Plugin { return &mockPlugin{} })
	defer brutus.ResetPlugins()

	c := NewCapability()

	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
		},
	}

	input := capmodel.Port{
		Port:    22,
		Service: "mock-test",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	err := c.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	assert.Len(t, emitted, 1, "should emit one risk from mock plugin")
}

func TestCapability_Invoke_PortOutOfRange(t *testing.T) {
	c := NewCapability()
	ctx := capability.ExecutionContext{Manual: true}

	input := capmodel.Port{
		Service: "ssh",
		Port:    70000,
		Parent:  capmodel.Asset{DNS: "example.com"},
	}
	err := c.Invoke(ctx, input, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

func TestCapability_Invoke_EmitterError(t *testing.T) {
	brutus.ResetPlugins()
	brutus.Register("mock-test", func() brutus.Plugin { return &mockPlugin{} })
	defer brutus.ResetPlugins()

	c := NewCapability()

	emitter := capability.EmitterFunc(func(models ...any) error {
		return fmt.Errorf("emit failed")
	})

	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
			{Name: "protocol", Value: "mock-test", Type: "string"},
		},
	}

	input := capmodel.Port{
		Port:    22,
		Service: "mock-test",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	err := c.Invoke(ctx, input, emitter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "emit failed")
}

func TestInvoke_RejectsNegativeRateLimit(t *testing.T) {
	orig := bruteFunc
	defer func() { bruteFunc = orig }()

	called := false
	bruteFunc = func(_ context.Context, _ *brutus.Config) ([]brutus.Result, error) {
		called = true
		return nil, nil
	}

	c := NewCapability()
	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
			{Name: "protocol", Value: "ssh", Type: "string"},
			{Name: "ratelimit", Value: "-1", Type: "float"},
		},
	}
	input := capmodel.Port{
		Port:    22,
		Service: "ssh",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	err := c.Invoke(ctx, input, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-negative")
	assert.False(t, called, "bruteFunc should not be called when ratelimit is negative")
}

func TestInvoke_ZeroRateLimitMeansUnlimited(t *testing.T) {
	orig := bruteFunc
	defer func() { bruteFunc = orig }()

	var capturedCfg *brutus.Config
	bruteFunc = func(_ context.Context, cfg *brutus.Config) ([]brutus.Result, error) {
		capturedCfg = cfg
		return nil, nil
	}

	c := NewCapability()
	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
			{Name: "protocol", Value: "ssh", Type: "string"},
			{Name: "ratelimit", Value: "0", Type: "float"},
		},
	}
	input := capmodel.Port{
		Port:    22,
		Service: "ssh",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}
	emitter := capability.EmitterFunc(func(_ ...any) error { return nil })

	err := c.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)
	assert.Equal(t, 0.0, capturedCfg.RateLimit)
}

func TestInvoke_PositiveRateLimitPropagates(t *testing.T) {
	orig := bruteFunc
	defer func() { bruteFunc = orig }()

	var capturedCfg *brutus.Config
	bruteFunc = func(_ context.Context, cfg *brutus.Config) ([]brutus.Result, error) {
		capturedCfg = cfg
		return nil, nil
	}

	c := NewCapability()
	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
			{Name: "protocol", Value: "ssh", Type: "string"},
			{Name: "ratelimit", Value: "2.5", Type: "float"},
		},
	}
	input := capmodel.Port{
		Port:    22,
		Service: "ssh",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}
	emitter := capability.EmitterFunc(func(_ ...any) error { return nil })

	err := c.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)
	assert.Equal(t, 2.5, capturedCfg.RateLimit)
}

func TestInvoke_PartialResultsOnBruteError(t *testing.T) {
	orig := bruteFunc
	defer func() { bruteFunc = orig }()

	bruteFunc = func(_ context.Context, _ *brutus.Config) ([]brutus.Result, error) {
		return []brutus.Result{
			{
				Protocol: "ssh",
				Target:   "127.0.0.1:22",
				Username: "admin",
				Password: "pass",
				Success:  true,
				Banner:   "SSH-2.0-OpenSSH",
			},
		}, fmt.Errorf("context deadline exceeded")
	}

	c := NewCapability()
	ctx := capability.ExecutionContext{
		Manual: true,
		Parameters: capability.Parameters{
			{Name: "usernames", Value: "admin", Type: "string"},
			{Name: "passwords", Value: "pass", Type: "string"},
			{Name: "protocol", Value: "ssh", Type: "string"},
		},
	}
	input := capmodel.Port{
		Port:    22,
		Service: "ssh",
		Parent:  capmodel.Asset{DNS: "127.0.0.1"},
	}

	var emitted []any
	emitter := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	err := c.Invoke(ctx, input, emitter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "brute force execution failed")
	assert.Contains(t, err.Error(), "context deadline exceeded")
	require.Len(t, emitted, 1)

	risk, ok := emitted[0].(capmodel.Risk)
	require.True(t, ok)
	assert.Equal(t, "Weak Credentials", risk.Name)
	assert.Equal(t, "brutus", risk.Source)
}
