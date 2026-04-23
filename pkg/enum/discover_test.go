// pkg/enum/discover_test.go
package enum

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oraclePlugin differentiates valid/invalid emails.
type oraclePlugin struct{ name string }

func (p *oraclePlugin) Name() string { return p.name }
func (p *oraclePlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	// Simulate: known-valid email returns exists, everything else doesn't
	exists := email == "known@company.com"
	return &Result{
		Service:    p.name,
		Email:      email,
		Exists:     exists,
		Confidence: ConfidenceHigh,
	}
}

// nonOraclePlugin always returns the same response.
type nonOraclePlugin struct{ name string }

func (p *nonOraclePlugin) Name() string { return p.name }
func (p *nonOraclePlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	return &Result{
		Service:    p.name,
		Email:      email,
		Exists:     false, // Always says not found
		Confidence: ConfidenceHigh,
	}
}

func TestDiscoverOracles_FindsOracle(t *testing.T) {
	resetPlugins()
	Register("oracle-svc", func() Plugin { return &oraclePlugin{name: "oracle-svc"} })
	Register("non-oracle", func() Plugin { return &nonOraclePlugin{name: "non-oracle"} })

	cfg := &DiscoverConfig{
		KnownValid: "known@company.com",
		Threads:    2,
		Timeout:    5 * time.Second,
	}

	results, err := DiscoverOracles(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Find results by service
	var oracleResult, nonOracleResult *OracleResult
	for i := range results {
		switch results[i].Service {
		case "oracle-svc":
			oracleResult = &results[i]
		case "non-oracle":
			nonOracleResult = &results[i]
		}
	}

	require.NotNil(t, oracleResult)
	assert.True(t, oracleResult.IsOracle)

	require.NotNil(t, nonOracleResult)
	assert.False(t, nonOracleResult.IsOracle)
}

func TestDiscoverOracles_RequiresKnownValid(t *testing.T) {
	cfg := &DiscoverConfig{}
	_, err := DiscoverOracles(context.Background(), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "known-valid")
}
