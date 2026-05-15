// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package brutus

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRateLimitApplied tests that rate limiting is applied when RateLimit > 0
func TestRateLimitApplied(t *testing.T) {
	// Register a test plugin that tracks call times
	var callCount atomic.Int32
	var callTimes []time.Time
	var mu sync.Mutex

	Register("test-rate", func() Plugin {
		return &testRateLimitPlugin{
			callCount: &callCount,
			callTimes: &callTimes,
			mu:        &mu,
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:    "test:1234",
		Protocol:  "test-rate",
		Usernames: []string{"user1", "user2", "user3", "user4"},
		Passwords: []string{"pass1", "pass2"},
		Threads:   2,
		Timeout:   time.Second,
		RateLimit: 10.0, // 10 requests per second
		Jitter:    0,
	}

	start := time.Now()
	results, err := Brute(config)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.Equal(t, 8, len(results)) // 4 users x 2 passwords

	// With 10 rps rate limit and 8 requests, should take at least 700ms
	// (0ms for first request, then 100ms intervals for remaining 7 requests)
	assert.GreaterOrEqual(t, duration.Milliseconds(), int64(700),
		"Rate limiting should enforce minimum delay between requests")
}

// TestRateLimitDisabled tests that no rate limiting is applied when RateLimit = 0
func TestRateLimitDisabled(t *testing.T) {
	var callCount atomic.Int32

	Register("test-no-rate", func() Plugin {
		return &testRateLimitPlugin{
			callCount: &callCount,
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:    "test:1234",
		Protocol:  "test-no-rate",
		Usernames: []string{"user1", "user2", "user3", "user4"},
		Passwords: []string{"pass1", "pass2"},
		Threads:   4,
		Timeout:   time.Second,
		RateLimit: 0, // No rate limiting
		Jitter:    0,
	}

	start := time.Now()
	results, err := Brute(config)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.Equal(t, 8, len(results)) // 4 users x 2 passwords

	// Without rate limiting, all requests should complete quickly
	// Allow up to 100ms for execution overhead
	assert.Less(t, duration.Milliseconds(), int64(100),
		"No rate limiting should allow fast parallel execution")
}

// TestJitterApplied tests that jitter adds randomness to rate limiting
func TestJitterApplied(t *testing.T) {
	var callTimes []time.Time
	var mu sync.Mutex

	Register("test-jitter", func() Plugin {
		return &testRateLimitPlugin{
			callTimes: &callTimes,
			mu:        &mu,
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:    "test:1234",
		Protocol:  "test-jitter",
		Usernames: []string{"user1", "user2", "user3", "user4"},
		Passwords: []string{"pass1", "pass2"},
		Threads:   1,
		Timeout:   time.Second,
		RateLimit: 10.0,                  // 10 requests per second (100ms between requests)
		Jitter:    50 * time.Millisecond, // Up to 50ms jitter
	}

	_, err := Brute(config)
	assert.NoError(t, err)

	// With jitter, intervals between requests should vary
	// Check that not all intervals are exactly 100ms
	mu.Lock()
	defer mu.Unlock()

	if len(callTimes) < 2 {
		t.Skip("Not enough call times to check jitter")
	}

	intervals := make([]int64, 0, len(callTimes)-1)
	for i := 1; i < len(callTimes); i++ {
		interval := callTimes[i].Sub(callTimes[i-1]).Milliseconds()
		intervals = append(intervals, interval)
	}

	// At least some intervals should differ (jitter adds randomness)
	allSame := true
	firstInterval := intervals[0]
	for _, interval := range intervals[1:] {
		if interval != firstInterval {
			allSame = false
			break
		}
	}

	assert.False(t, allSame, "Jitter should create varying intervals between requests")
}

// testRateLimitPlugin is a test plugin that records call times
type testRateLimitPlugin struct {
	callCount *atomic.Int32
	callTimes *[]time.Time
	mu        *sync.Mutex
}

func (p *testRateLimitPlugin) Name() string {
	return "test-rate-limit"
}

func (p *testRateLimitPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	if p.callCount != nil {
		p.callCount.Add(1)
	}

	if p.callTimes != nil && p.mu != nil {
		p.mu.Lock()
		*p.callTimes = append(*p.callTimes, time.Now())
		p.mu.Unlock()
	}

	// Simulate quick authentication check
	return &Result{
		Protocol: "test-rate-limit",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Duration: time.Millisecond,
	}
}

// TestSubSecondRateLimit tests that fractional rates (sub-1 RPS) work correctly
func TestSubSecondRateLimit(t *testing.T) {
	tests := []struct {
		name          string
		rateLimit     float64
		numRequests   int
		minDurationMS int64
		description   string
	}{
		{
			name:          "0.5 RPS (1 request every 2 seconds)",
			rateLimit:     0.5,
			numRequests:   2,
			minDurationMS: 2000, // First request immediate, second after 2s
			description:   "0.5 RPS means 1 request every 2 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var callCount atomic.Int32

			// Use unique plugin name per test case to avoid conflicts
			pluginName := "test-subsecond-" + tt.name
			Register(pluginName, func() Plugin {
				return &testRateLimitPlugin{
					callCount: &callCount,
				}
			})
			defer ResetPlugins()

			config := &Config{
				Target:    "test:1234",
				Protocol:  pluginName,
				Usernames: []string{"user1", "user2"}, // 2 users
				Passwords: []string{"pass1"},          // 1 password = 2 total requests
				Threads:   1,                          // Single thread for predictable timing
				Timeout:   time.Second,
				RateLimit: tt.rateLimit,
				Jitter:    0,
			}

			start := time.Now()
			results, err := Brute(config)
			duration := time.Since(start)

			assert.NoError(t, err)
			assert.Equal(t, tt.numRequests, len(results))

			// Verify minimum duration matches expected rate limiting
			assert.GreaterOrEqual(t, duration.Milliseconds(), tt.minDurationMS,
				"Rate limiting at %.2f RPS should enforce minimum delay. %s",
				tt.rateLimit, tt.description)
		})
	}
}

// TestJitterRespectsContextCancellation tests that jitter sleep respects context cancellation.
// When the caller cancels the context (e.g., Ctrl+C), goroutines sleeping in jitter
// should wake up immediately, not continue sleeping for the full jitter duration.
func TestJitterRespectsContextCancellation(t *testing.T) {
	Register("test-jitter-cancel", func() Plugin {
		return &testJitterCancelPlugin{}
	})
	defer ResetPlugins()

	config := &Config{
		Target:    "test:1234",
		Protocol:  "test-jitter-cancel",
		Usernames: []string{"user1", "user2", "user3", "user4"},
		Passwords: []string{"pass1", "pass2", "pass3"},
		Threads:   4,
		Timeout:   time.Second,
		RateLimit: 100.0,           // Enable rate limiting to trigger jitter code path
		Jitter:    5 * time.Second, // Long jitter to make bug obvious
	}

	// Cancel context after a short delay to simulate Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	results, err := BruteWithContext(ctx, config)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	// Some results may have been collected before cancellation
	_ = results

	// Without the fix, goroutines sleep for full jitter (5s) even after context cancel.
	// With the fix, they exit immediately when context is canceled.
	// Allow generous margin for CI environment variability (slow VMs, CPU contention).
	assert.Less(t, elapsed, 3*time.Second,
		"Workers should exit quickly on context cancellation, not sleep full jitter duration (5s). Actual: %v", elapsed)
}

// testJitterCancelPlugin always returns failure (used to test context cancellation during jitter)
type testJitterCancelPlugin struct{}

func (p *testJitterCancelPlugin) Name() string {
	return "test-jitter-cancel"
}

func (p *testJitterCancelPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "test-jitter-cancel",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Duration: 10 * time.Millisecond,
	}
}
