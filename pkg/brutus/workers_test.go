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

// TestExecuteWorkerPool_PanicResultsNotDropped is a regression test for a bug
// where the panic-recovery path used mu.TryLock() instead of mu.Lock(). Under
// mutex contention (many workers panicking concurrently), TryLock would fail
// and the panic Result was silently discarded instead of recorded. This test
// drives enough concurrent panicking attempts to create genuine contention and
// asserts the conservation property: every credential attempt that panics
// still produces exactly one recorded Result carrying the panic error.
func TestExecuteWorkerPool_PanicResultsNotDropped(t *testing.T) {
	mock := &panickingPlugin{}

	const numPasswords = 300
	passwords := make([]string, numPasswords)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("pass%d", i)
	}

	cfg := &Config{
		Target:    "test:22",
		Protocol:  "panic-mock",
		Usernames: []string{"user"},
		Passwords: passwords,
		Threads:   32,
		Timeout:   1 * time.Second,
		Plugin:    mock,
	}

	results, err := Brute(cfg)
	assert.NoError(t, err)

	invocations := int(atomic.LoadInt64(&mock.invocations))
	dropped := invocations - len(results)
	assert.Equal(t, invocations, len(results),
		"dropped %d of %d panic results (invocations=%d, results=%d)",
		dropped, invocations, invocations, len(results))

	for _, r := range results {
		assert.Error(t, r.Error, "panic result should carry a non-nil Error")
	}
}

// panickingPlugin counts every Test invocation and then panics, simulating a
// plugin bug. The worker pool must recover from the panic and still record a
// Result for every invocation.
type panickingPlugin struct {
	invocations int64
}

func (p *panickingPlugin) Name() string { return "panic-mock" }

func (p *panickingPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	atomic.AddInt64(&p.invocations, 1)
	panic("simulated plugin panic for regression test")
}

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
