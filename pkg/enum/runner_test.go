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

package enum

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// T10: EnumerateWithPlugin
// ---------------------------------------------------------------------------

// stubPlugin is an in-test implementation of Plugin that always returns a
// configurable result. It is safe for concurrent use (stateless).
type stubPlugin struct {
	name   string
	exists bool
}

func (s *stubPlugin) Name() string { return s.name }

func (s *stubPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	return &Result{
		Service:    s.name,
		Email:      email,
		Exists:     s.exists,
		Confidence: ConfidenceHigh,
	}
}

// TestEnumerateWithPlugin_FanOut verifies that EnumerateWithPlugin fans the
// call out over all subjects (Emails) and returns one result per subject,
// all with the stub plugin's configured outcome.
func TestEnumerateWithPlugin_FanOut(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "stub-oracle", exists: true}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Emails:  []string{"a", "b", "c"},
		Threads: 2,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 3, "must return exactly one result per subject")

	for _, r := range results {
		assert.True(t, r.Exists, "stub always returns Exists=true")
		assert.Equal(t, "stub-oracle", r.Service,
			"Service must match Plugin.Name()")
		assert.NoError(t, r.Error)
	}

	// Verify all three subjects appeared in results.
	subjects := make(map[string]bool)
	for _, r := range results {
		subjects[r.Email] = true
	}
	assert.True(t, subjects["a"], "subject 'a' must be in results")
	assert.True(t, subjects["b"], "subject 'b' must be in results")
	assert.True(t, subjects["c"], "subject 'c' must be in results")
}

// TestEnumerateWithPlugin_EmptyEmails verifies that EnumerateWithPlugin
// returns a "emails required" validation error when Emails is empty.
func TestEnumerateWithPlugin_EmptyEmails(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "stub", exists: true}

	_, err := EnumerateWithPlugin(context.Background(), &Config{
		Emails:  []string{},
		Threads: 2,
	}, p)

	require.Error(t, err, "empty Emails must return an error")
	assert.Contains(t, err.Error(), "emails required",
		"error must mention 'emails required' (mirrors enum.go:38)")
}

// TestEnumerateWithPlugin_AbsentResult verifies that a stub returning
// Exists=false produces correct absent results.
func TestEnumerateWithPlugin_AbsentResult(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "absent-oracle", exists: false}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Emails:  []string{"user1", "user2"},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		assert.False(t, r.Exists, "stub returns Exists=false for all subjects")
		assert.NoError(t, r.Error)
		assert.Equal(t, "absent-oracle", r.Service)
	}
}

// TestEnumerateWithPlugin_ServiceNameFromPlugin verifies that the Service
// field in each result is set to Plugin.Name().
func TestEnumerateWithPlugin_ServiceNameFromPlugin(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "my-custom-oracle", exists: true}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Emails:  []string{"test@example.com"},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "my-custom-oracle", results[0].Service)
}

// TestEnumerateWithPlugin_SingleThread verifies that EnumerateWithPlugin works
// correctly with Threads=1 (no concurrency edge cases).
func TestEnumerateWithPlugin_SingleThread(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "single-thread-oracle", exists: true}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Emails:  []string{"a", "b", "c", "d", "e"},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 5, "single-threaded must still produce all results")
}
