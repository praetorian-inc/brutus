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
	"github.com/stretchr/testify/require"
)

// TestRetryOnConnectionError tests that credentials are retried on connection error
func TestRetryOnConnectionError(t *testing.T) {
	var callCount atomic.Int32

	Register("test-retry", func() Plugin {
		return &testRetryPlugin{
			callCount:  &callCount,
			failFirstN: 2, // First 2 calls return connection error
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:     "test:1234",
		Protocol:   "test-retry",
		Usernames:  []string{"user1"},
		Passwords:  []string{"pass1"},
		Threads:    1,
		Timeout:    time.Second,
		MaxRetries: 3,
	}

	results, err := Brute(config)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Should succeed on 3rd attempt (after 2 connection errors)
	assert.True(t, results[0].Success, "should succeed after retries")
	assert.Nil(t, results[0].Error)
	// Total calls: 3 (2 failures + 1 success)
	assert.Equal(t, int32(3), callCount.Load())
}

// TestRetryExhausted tests that when all retries fail, the error is recorded
func TestRetryExhausted(t *testing.T) {
	var callCount atomic.Int32

	Register("test-retry-exhaust", func() Plugin {
		return &testRetryPlugin{
			callCount:  &callCount,
			failFirstN: 100, // Always fail
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:     "test:1234",
		Protocol:   "test-retry-exhaust",
		Usernames:  []string{"user1"},
		Passwords:  []string{"pass1"},
		Threads:    1,
		Timeout:    time.Second,
		MaxRetries: 2,
	}

	results, err := Brute(config)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Should fail with connection error after exhausting retries
	assert.False(t, results[0].Success)
	assert.NotNil(t, results[0].Error)
	// Total calls: 3 (1 initial + 2 retries)
	assert.Equal(t, int32(3), callCount.Load())
}

// TestNoRetryWhenDisabled tests that retries are disabled when MaxRetries=0
func TestNoRetryWhenDisabled(t *testing.T) {
	var callCount atomic.Int32

	Register("test-no-retry", func() Plugin {
		return &testRetryPlugin{
			callCount:  &callCount,
			failFirstN: 100,
		}
	})
	defer ResetPlugins()

	config := &Config{
		Target:     "test:1234",
		Protocol:   "test-no-retry",
		Usernames:  []string{"user1"},
		Passwords:  []string{"pass1"},
		Threads:    1,
		Timeout:    time.Second,
		MaxRetries: 0, // Disabled
	}

	results, err := Brute(config)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Success)
	assert.NotNil(t, results[0].Error)
	// Only 1 call - no retries
	assert.Equal(t, int32(1), callCount.Load())
}

// TestNoRetryOnAuthFailure tests that auth failures are NOT retried
func TestNoRetryOnAuthFailure(t *testing.T) {
	var callCount atomic.Int32

	Register("test-no-retry-auth", func() Plugin {
		return &testAuthFailPlugin{callCount: &callCount}
	})
	defer ResetPlugins()

	config := &Config{
		Target:     "test:1234",
		Protocol:   "test-no-retry-auth",
		Usernames:  []string{"user1"},
		Passwords:  []string{"wrongpass"},
		Threads:    1,
		Timeout:    time.Second,
		MaxRetries: 3,
	}

	results, err := Brute(config)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Auth failure - should NOT be retried
	assert.False(t, results[0].Success)
	assert.Nil(t, results[0].Error) // Auth failure, not connection error
	assert.Equal(t, int32(1), callCount.Load(), "auth failures should not be retried")
}

// testRetryPlugin simulates connection errors for first N calls, then succeeds
type testRetryPlugin struct {
	callCount  *atomic.Int32
	failFirstN int
}

func (p *testRetryPlugin) Name() string { return "test-retry" }

func (p *testRetryPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	call := int(p.callCount.Add(1))
	if call <= p.failFirstN {
		return &Result{
			Protocol: "test-retry",
			Target:   target,
			Username: username,
			Password: password,
			Success:  false,
			Error:    fmt.Errorf("connection error: EOF"),
			Duration: time.Millisecond,
		}
	}
	return &Result{
		Protocol: "test-retry",
		Target:   target,
		Username: username,
		Password: password,
		Success:  true,
		Duration: time.Millisecond,
	}
}

// testAuthFailPlugin always returns auth failure (Error=nil, Success=false)
type testAuthFailPlugin struct {
	callCount *atomic.Int32
}

func (p *testAuthFailPlugin) Name() string { return "test-auth-fail" }

func (p *testAuthFailPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	p.callCount.Add(1)
	return &Result{
		Protocol: "test-auth-fail",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Error:    nil, // Auth failure, not connection error
		Duration: time.Millisecond,
	}
}
