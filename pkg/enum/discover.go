// pkg/enum/discover.go
package enum

import (
	"context"
	"fmt"
	"time"
)

// DiscoverConfig holds configuration for oracle discovery mode.
type DiscoverConfig struct {
	KnownValid string        // a known-valid email address for calibration
	Services   []string      // services to test (empty = all)
	Threads    int           // concurrent workers
	Timeout    time.Duration // per-check timeout
	Verbose    bool          // verbose output
}

// DiscoverOracles tests registered services to find which ones act as
// enumeration oracles by comparing responses for a known-valid email
// vs a generated invalid email.
func DiscoverOracles(ctx context.Context, cfg *DiscoverConfig) ([]OracleResult, error) {
	if cfg.KnownValid == "" {
		return nil, fmt.Errorf("known-valid email required for oracle discovery")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Threads == 0 {
		cfg.Threads = 10
	}

	return runDiscovery(ctx, cfg)
}

// runDiscovery is the internal implementation placeholder.
func runDiscovery(_ context.Context, _ *DiscoverConfig) ([]OracleResult, error) {
	return nil, nil
}
