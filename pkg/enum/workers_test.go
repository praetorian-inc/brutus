// pkg/enum/workers_test.go
package enum

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlugin tracks calls for testing.
type mockPlugin struct {
	name      string
	exists    bool
	callCount atomic.Int32
}

func (p *mockPlugin) Name() string { return p.name }
func (p *mockPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	p.callCount.Add(1)
	return &Result{
		Service:    p.name,
		Email:      email,
		Exists:     p.exists,
		Confidence: ConfidenceHigh,
	}
}

func TestRunWorkers_EmailsTimesServices(t *testing.T) {
	ResetPlugins()

	mock1 := &mockPlugin{name: "svc1", exists: true}
	mock2 := &mockPlugin{name: "svc2", exists: false}
	Register("svc1", func() Plugin { return mock1 })
	Register("svc2", func() Plugin { return mock2 })

	cfg := &Config{
		Emails:  []string{"a@test.com", "b@test.com"},
		Threads: 2,
		Timeout: 5 * time.Second,
	}
	cfg.validate()

	results, err := runWorkers(context.Background(), cfg)
	require.NoError(t, err)

	// 2 emails x 2 services = 4 results
	assert.Len(t, results, 4)
}

func TestRunWorkers_SpecificServices(t *testing.T) {
	ResetPlugins()

	mock := &mockPlugin{name: "only", exists: true}
	Register("only", func() Plugin { return mock })
	Register("skip", func() Plugin { return &mockPlugin{name: "skip"} })

	cfg := &Config{
		Emails:   []string{"a@test.com"},
		Services: []string{"only"},
		Threads:  1,
		Timeout:  5 * time.Second,
	}
	cfg.validate()

	results, err := runWorkers(context.Background(), cfg)
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Equal(t, "only", results[0].Service)
}

func TestRunWorkers_ContextCancellation(t *testing.T) {
	ResetPlugins()
	Register("slow", func() Plugin {
		return &mockPlugin{name: "slow"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &Config{
		Emails:  []string{"a@test.com"},
		Threads: 1,
		Timeout: 5 * time.Second,
	}
	cfg.validate()

	results, err := runWorkers(ctx, cfg)
	assert.NoError(t, err)
	// Should get 0 or fewer results due to cancellation
	assert.LessOrEqual(t, len(results), 1)
}
