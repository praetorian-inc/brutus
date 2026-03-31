// pkg/enum/integration_test.go
package enum

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerateWithContext_EndToEnd(t *testing.T) {
	ResetPlugins()
	Register("mock-saas", func() Plugin {
		return &oraclePlugin{name: "mock-saas"}
	})

	cfg := &Config{
		Emails:  []string{"known@company.com", "unknown@company.com"},
		Threads: 2,
		Timeout: 5 * time.Second,
	}

	results, err := EnumerateWithContext(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// known@company.com should exist
	var knownResult *Result
	for i := range results {
		if results[i].Email == "known@company.com" {
			knownResult = &results[i]
		}
	}
	require.NotNil(t, knownResult)
	assert.True(t, knownResult.Exists)
}
