// pkg/enum/discover.go
package enum

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
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

// runDiscovery executes oracle discovery for all services.
func runDiscovery(ctx context.Context, cfg *DiscoverConfig) ([]OracleResult, error) {
	services := cfg.Services
	if len(services) == 0 {
		services = ListPlugins()
	}

	invalidEmail := generateInvalidEmail(cfg.KnownValid)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.Threads)

	var (
		results []OracleResult
		mu      sync.Mutex
	)

	for _, svcName := range services {
		svcName := svcName

		g.Go(func() error {
			plug, err := GetPlugin(svcName)
			if err != nil {
				mu.Lock()
				results = append(results, OracleResult{
					Service: svcName,
					Error:   err,
				})
				mu.Unlock()
				return nil
			}

			// Check if plugin implements OraclePlugin for custom discovery
			if op, ok := plug.(OraclePlugin); ok {
				result := op.Discover(ctx, cfg.KnownValid, cfg.Timeout)
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
				return nil
			}

			// Fallback: compare Check() for known-valid vs invalid
			validResult := plug.Check(ctx, cfg.KnownValid, cfg.Timeout)
			invalidResult := plug.Check(ctx, invalidEmail, cfg.Timeout)

			oracleResult := compareResults(svcName, validResult, invalidResult)

			mu.Lock()
			results = append(results, oracleResult)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return results, err
	}

	return results, nil
}

// compareResults determines if a service is an oracle based on response differences.
func compareResults(service string, validResult, invalidResult *Result) OracleResult {
	// If either check errored, we can't determine oracle status
	if validResult.Error != nil || invalidResult.Error != nil {
		errToReport := validResult.Error
		if errToReport == nil {
			errToReport = invalidResult.Error
		}
		return OracleResult{
			Service: service,
			Error:   errToReport,
		}
	}

	// Different Exists results = oracle
	if validResult.Exists != invalidResult.Exists {
		return OracleResult{
			Service:    service,
			IsOracle:   true,
			Confidence: ConfidenceHigh,
			Method:     "response_body",
		}
	}

	return OracleResult{
		Service:    service,
		IsOracle:   false,
		Confidence: ConfidenceHigh,
	}
}

// generateInvalidEmail creates a random invalid email using the same domain.
func generateInvalidEmail(validEmail string) string {
	parts := strings.SplitN(validEmail, "@", 2)
	if len(parts) != 2 {
		return "invalid-enum-test-" + randomHex(8) + "@example.com"
	}
	return "invalid-enum-test-" + randomHex(8) + "@" + parts[1]
}

// randomHex returns n random hex characters.
func randomHex(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
