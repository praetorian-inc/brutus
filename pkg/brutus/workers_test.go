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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCaptureBanner_EmptyUsernames(t *testing.T) {
	// Setup: Config with only Credentials (no Usernames), HTTP protocol, LLM enabled
	cfg := &Config{
		Target:   "example.com:80",
		Protocol: "http",
		Credentials: []Credential{
			{Username: "admin", Password: "password123"},
		},
		Usernames: []string{}, // EMPTY - triggers the bug
		Timeout:   10 * time.Second,
		LLMConfig: &LLMConfig{
			Enabled:  true,
			Provider: "claude",
		},
	}

	// Create mock plugin
	mockPlugin := &mockHTTPPlugin{}

	// This should NOT panic
	ctx := context.Background()
	banner := captureBanner(ctx, cfg, mockPlugin)

	// Should return a valid BannerInfo with empty Banner (not crash)
	assert.Equal(t, "http", banner.Protocol)
	assert.Equal(t, "example.com:80", banner.Target)
	// Banner may be empty, which is fine
}

// TestThreadsClampsConcurrency is a regression test for a bug where
// Config.Threads was only defaulted when equal to 0 (`if c.Threads == 0`),
// leaving negative values (e.g. Threads: -1) untouched. errgroup.SetLimit
// treats a negative limit as unlimited, so a negative Threads value spawned
// one goroutine per credential instead of being bounded.
//
// This test drives real credential attempts through Brute() with a mock
// plugin that tracks the high-water mark of concurrently in-flight
// Test() calls, and asserts the observed peak concurrency never exceeds
// the expected effective limit. A field-equality check on cfg.Threads would
// not catch this bug, since the bug is about how the (correctly defaulted
// or not) value is enforced by the worker pool, not about the field value
// itself.
func TestThreadsClampsConcurrency(t *testing.T) {
	// Enough credentials that unbounded concurrency (the bug) would clearly
	// exceed any of the expected bounds below.
	const numCredentials = 150

	usernames := make([]string, numCredentials)
	for i := range usernames {
		usernames[i] = fmt.Sprintf("user%d", i)
	}

	tests := []struct {
		name        string
		threads     int
		expectedMax int64
	}{
		{name: "negative threads clamps to default limit", threads: -1, expectedMax: 10},
		{name: "zero threads defaults to default limit", threads: 0, expectedMax: 10},
		{name: "positive threads respected as limit", threads: 3, expectedMax: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &concurrencyTrackingPlugin{}

			cfg := &Config{
				Target:    "test:22",
				Protocol:  "mock-concurrency",
				Usernames: usernames,
				Passwords: []string{"password"},
				Threads:   tt.threads,
				Timeout:   1 * time.Second,
				Plugin:    plugin,
			}

			_, err := Brute(cfg)
			assert.NoError(t, err)

			peak := atomic.LoadInt64(&plugin.peak)
			assert.LessOrEqual(t, peak, tt.expectedMax,
				"observed peak concurrency %d exceeds expected bound %d (Threads=%d)",
				peak, tt.expectedMax, tt.threads)
		})
	}
}

// concurrencyTrackingPlugin is a mock Plugin that records the high-water
// mark of concurrently in-flight Test() calls using atomic operations, so
// tests can assert on real observed concurrency rather than config values.
type concurrencyTrackingPlugin struct {
	current int64
	peak    int64
}

func (p *concurrencyTrackingPlugin) Name() string { return "mock-concurrency" }

func (p *concurrencyTrackingPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	n := atomic.AddInt64(&p.current, 1)

	// CAS loop to record the high-water mark without losing updates from
	// concurrent goroutines.
	for {
		old := atomic.LoadInt64(&p.peak)
		if n <= old {
			break
		}
		if atomic.CompareAndSwapInt64(&p.peak, old, n) {
			break
		}
	}

	// Hold the "attempt" open briefly so overlapping calls are observable.
	time.Sleep(5 * time.Millisecond)

	atomic.AddInt64(&p.current, -1)

	return &Result{
		Protocol: "mock-concurrency",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}
}

type mockHTTPPlugin struct{}

func (m *mockHTTPPlugin) Name() string { return "http" }

func (m *mockHTTPPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "http",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Banner:   "HTTP/1.1 401 Unauthorized",
	}
}
