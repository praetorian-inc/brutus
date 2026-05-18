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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMaxAttempts verifies that the MaxAttempts config limits password attempts per user
func TestMaxAttempts(t *testing.T) {
	// Create a mock plugin that tracks attempts per user
	mock := &mockPluginWithTracking{
		attempts: make(map[string]int),
	}

	// Register the mock plugin
	ResetPlugins()
	Register("mock", func() Plugin { return mock })

	// Config with 2 users, 5 passwords each = 10 total attempts normally
	// With MaxAttempts=3, should only test 3 passwords per user = 6 attempts
	cfg := &Config{
		Target:      "test:22",
		Protocol:    "mock",
		Usernames:   []string{"user1", "user2"},
		Passwords:   []string{"pass1", "pass2", "pass3", "pass4", "pass5"},
		Threads:     2,
		Timeout:     1 * time.Second,
		MaxAttempts: 3, // Limit to 3 attempts per user
	}

	// Run brute force
	_, err := Brute(cfg)
	assert.NoError(t, err)

	// Verify each user was tested at most 3 times
	assert.LessOrEqual(t, mock.attempts["user1"], 3, "user1 should have at most 3 attempts")
	assert.LessOrEqual(t, mock.attempts["user2"], 3, "user2 should have at most 3 attempts")

	// Verify total attempts is at most 6 (3 per user)
	totalAttempts := mock.attempts["user1"] + mock.attempts["user2"]
	assert.LessOrEqual(t, totalAttempts, 6, "total attempts should be at most 6")
}

// TestMaxAttemptsUnlimited verifies that MaxAttempts=0 means unlimited
func TestMaxAttemptsUnlimited(t *testing.T) {
	mock := &mockPluginWithTracking{
		attempts: make(map[string]int),
	}

	ResetPlugins()
	Register("mock", func() Plugin { return mock })

	cfg := &Config{
		Target:      "test:22",
		Protocol:    "mock",
		Usernames:   []string{"user1"},
		Passwords:   []string{"pass1", "pass2", "pass3", "pass4", "pass5"},
		Threads:     2,
		Timeout:     1 * time.Second,
		MaxAttempts: 0, // Unlimited
	}

	_, err := Brute(cfg)
	assert.NoError(t, err)

	// With unlimited attempts, should test all 5 passwords
	assert.Equal(t, 5, mock.attempts["user1"], "user1 should have 5 attempts")
}

// TestSprayOrdering verifies that credentials are always reordered to loop
// users first (spray ordering) to avoid account lockout.
func TestSprayOrdering(t *testing.T) {
	// Create a mock plugin that records the order of attempts
	mock := &mockPluginWithOrder{
		order: []string{},
	}

	ResetPlugins()
	Register("mock", func() Plugin { return mock })

	cfg := &Config{
		Target:    "test:22",
		Protocol:  "mock",
		Usernames: []string{"user1", "user2"},
		Passwords: []string{"pass1", "pass2"},
		Threads:   1, // Single thread to ensure sequential processing
		Timeout:   1 * time.Second,
	}

	_, err := Brute(cfg)
	assert.NoError(t, err)

	// Spray ordering: try each password across all users before moving
	// to the next password.
	// Expected: user1:pass1, user2:pass1, user1:pass2, user2:pass2
	assert.Len(t, mock.order, 4, "should have 4 attempts")

	// Verify first two attempts are both with pass1
	assert.Contains(t, mock.order[0], "pass1", "first attempt should be pass1")
	assert.Contains(t, mock.order[1], "pass1", "second attempt should be pass1")

	// Verify last two attempts are both with pass2
	assert.Contains(t, mock.order[2], "pass2", "third attempt should be pass2")
	assert.Contains(t, mock.order[3], "pass2", "fourth attempt should be pass2")
}

// TestReorderForSpray tests the reorderForSpray helper function directly
func TestReorderForSpray(t *testing.T) {
	tests := []struct {
		name     string
		input    []credential
		expected []credential
	}{
		{
			name: "basic spray reordering",
			input: []credential{
				{username: "user1", password: "pass1"},
				{username: "user1", password: "pass2"},
				{username: "user2", password: "pass1"},
				{username: "user2", password: "pass2"},
			},
			expected: []credential{
				{username: "user1", password: "pass1"},
				{username: "user2", password: "pass1"},
				{username: "user1", password: "pass2"},
				{username: "user2", password: "pass2"},
			},
		},
		{
			name:     "empty input",
			input:    []credential{},
			expected: []credential{},
		},
		{
			name: "single credential",
			input: []credential{
				{username: "user1", password: "pass1"},
			},
			expected: []credential{
				{username: "user1", password: "pass1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reorderForSpray(tt.input)
			assert.Equal(t, len(tt.expected), len(result), "length should match")

			// Verify the reordering is correct
			for i := range tt.expected {
				assert.Equal(t, tt.expected[i].username, result[i].username,
					"username at position %d should match", i)
				assert.Equal(t, tt.expected[i].password, result[i].password,
					"password at position %d should match", i)
			}
		})
	}
}

// TestMaxAttemptsWithSprayOrdering verifies combining max attempts with spray ordering
func TestMaxAttemptsWithSprayOrdering(t *testing.T) {
	mock := &mockPluginCombined{
		attempts: make(map[string]int),
		order:    []string{},
	}

	ResetPlugins()
	Register("mock", func() Plugin { return mock })

	cfg := &Config{
		Target:      "test:22",
		Protocol:    "mock",
		Usernames:   []string{"user1", "user2"},
		Passwords:   []string{"pass1", "pass2", "pass3"},
		Threads:     1,
		Timeout:     1 * time.Second,
		MaxAttempts: 2, // Max 2 attempts per user
	}

	_, err := Brute(cfg)
	assert.NoError(t, err)

	// Verify max attempts per user
	assert.LessOrEqual(t, mock.attempts["user1"], 2, "user1 should have at most 2 attempts")
	assert.LessOrEqual(t, mock.attempts["user2"], 2, "user2 should have at most 2 attempts")

	// Spray ordering still applies, but stops at 2 per user
	// Expected: user1:pass1, user2:pass1, user1:pass2, user2:pass2
	// (pass3 should be skipped due to MaxAttempts=2)
	totalAttempts := len(mock.order)
	assert.LessOrEqual(t, totalAttempts, 4, "total attempts should be at most 4")
}

// Mock plugin implementations for testing

// mockPluginWithTracking tracks number of attempts per username
type mockPluginWithTracking struct {
	mu       sync.Mutex
	attempts map[string]int
}

func (m *mockPluginWithTracking) Name() string { return "mock" }

func (m *mockPluginWithTracking) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	m.mu.Lock()
	m.attempts[username]++
	m.mu.Unlock()

	return &Result{
		Protocol: "mock",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Duration: 1 * time.Millisecond,
	}
}

// mockPluginWithOrder records the order of attempts
type mockPluginWithOrder struct {
	mu    sync.Mutex
	order []string
}

func (m *mockPluginWithOrder) Name() string { return "mock" }

func (m *mockPluginWithOrder) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	m.mu.Lock()
	m.order = append(m.order, username+":"+password)
	m.mu.Unlock()

	return &Result{
		Protocol: "mock",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Duration: 1 * time.Millisecond,
	}
}

// mockPluginCombined tracks both attempts and order
type mockPluginCombined struct {
	mu       sync.Mutex
	attempts map[string]int
	order    []string
}

func (m *mockPluginCombined) Name() string { return "mock" }

func (m *mockPluginCombined) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	m.mu.Lock()
	m.attempts[username]++
	m.order = append(m.order, username+":"+password)
	m.mu.Unlock()

	return &Result{
		Protocol: "mock",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Duration: 1 * time.Millisecond,
	}
}
