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
	"errors"
	"sync"
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
		Targets: []Target{{Email: "a"}, {Email: "b"}, {Email: "c"}},
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
		Targets: []Target{},
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
		Targets: []Target{{Email: "user1"}, {Email: "user2"}},
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
		Targets: []Target{{Email: "test@example.com"}},
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
		Targets: []Target{{Email: "a"}, {Email: "b"}, {Email: "c"}, {Email: "d"}, {Email: "e"}},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 5, "single-threaded must still produce all results")
}

// ---------------------------------------------------------------------------
// 10T-535: EnumerateWithPlugin name propagation (framework half)
//
// The generator (Candidate.Target) already knows First/Last. This section
// verifies the framework carries that name through to Result without
// disturbing what the Plugin interface sees, and without ever inventing a
// name for a Target that didn't have one.
// ---------------------------------------------------------------------------

// recordingPlugin is a stub Plugin that records every email it was asked to
// Check, so tests can assert exactly what the framework passed into the
// Plugin contract. Safe for concurrent use: checked is protected by mu.
type recordingPlugin struct {
	name   string
	exists bool

	mu      sync.Mutex
	checked []string
}

func (r *recordingPlugin) Name() string { return r.name }

func (r *recordingPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	r.mu.Lock()
	r.checked = append(r.checked, email)
	r.mu.Unlock()

	return &Result{
		Service:    r.name,
		Email:      email,
		Exists:     r.exists,
		Confidence: ConfidenceHigh,
	}
}

// erroringPlugin is a stub Plugin that always returns a service error from
// Check, used to verify that name-stamping survives the error path.
type erroringPlugin struct {
	name string
}

func (e *erroringPlugin) Name() string { return e.name }

func (e *erroringPlugin) Check(_ context.Context, email string, _ time.Duration) *Result {
	return &Result{
		Service: e.name,
		Email:   email,
		Error:   errors.New("service unavailable"),
	}
}

// TestEnumerateWithPlugin_NameCorrelation is THE CORE TEST for the framework
// half of 10T-535: EnumerateWithPlugin must stamp each Result with the
// First/Last of the Target that actually produced it, not just "some" name
// drawn from the batch. Using >=2 targets with DIFFERENT names is
// deliberate — a bug that stamped every Result with (say) the first
// target's name would still make a weaker "a name is present" assertion
// pass, but fails this one because each result is correlated back to its
// originating Target by Email.
//
// Correlating by Email rather than by result index is deliberate: neither
// TestEnumerateWithPlugin_FanOut nor TestEnumerateWithPlugin_SingleThread
// assert anything about result order (FanOut checks membership via a map;
// SingleThread only checks length), because runTasks appends results from
// concurrent goroutines under a mutex with no ordering guarantee relative to
// submission order. This test follows that same established expectation.
func TestEnumerateWithPlugin_NameCorrelation(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "name-oracle", exists: true}

	targets := []Target{
		{Email: "alice@example.com", First: "Alice", Last: "Anderson"},
		{Email: "bob@example.com", First: "Bob", Last: "Baker"},
	}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Targets: targets,
		Threads: 2,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 2)

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	aliceResult, ok := byEmail["alice@example.com"]
	require.True(t, ok, "result for alice@example.com must be present")
	assert.Equal(t, "Alice", aliceResult.First, "alice's result must carry Alice's First, not another target's")
	assert.Equal(t, "Anderson", aliceResult.Last, "alice's result must carry Alice's Last, not another target's")

	bobResult, ok := byEmail["bob@example.com"]
	require.True(t, ok, "result for bob@example.com must be present")
	assert.Equal(t, "Bob", bobResult.First, "bob's result must carry Bob's First, not another target's")
	assert.Equal(t, "Baker", bobResult.Last, "bob's result must carry Bob's Last, not another target's")
}

// TestEnumerateWithPlugin_EmptyNameYieldsEmptyResult verifies that a Target
// with no First/Last (the --email-file case: an address supplied directly
// rather than generated) produces a Result with empty First/Last. The
// framework must not invent or derive a name when the Target didn't carry
// one.
func TestEnumerateWithPlugin_EmptyNameYieldsEmptyResult(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "supplied-oracle", exists: true}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Targets: []Target{{Email: "supplied@example.com"}},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "supplied@example.com", results[0].Email)
	assert.Empty(t, results[0].First, "First must be empty for a supplied (non-generated) address")
	assert.Empty(t, results[0].Last, "Last must be empty for a supplied (non-generated) address")
}

// TestEnumerateWithPlugin_MixedNamedAndUnnamed verifies that in a batch
// containing both generated (named) and supplied (unnamed) targets, each
// Result carries exactly what its own Target had — no cross-contamination
// in either direction.
func TestEnumerateWithPlugin_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()
	p := &stubPlugin{name: "mixed-oracle", exists: true}

	targets := []Target{
		{Email: "named@example.com", First: "Carol", Last: "Chen"},
		{Email: "unnamed@example.com"},
	}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Targets: targets,
		Threads: 2,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 2)

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	named, ok := byEmail["named@example.com"]
	require.True(t, ok, "result for named@example.com must be present")
	assert.Equal(t, "Carol", named.First, "named target's result must carry its First")
	assert.Equal(t, "Chen", named.Last, "named target's result must carry its Last")

	unnamed, ok := byEmail["unnamed@example.com"]
	require.True(t, ok, "result for unnamed@example.com must be present")
	assert.Empty(t, unnamed.First, "unnamed target's result must not have an invented First")
	assert.Empty(t, unnamed.Last, "unnamed target's result must not have an invented Last")
}

// TestEnumerateWithPlugin_PluginReceivesOnlyEmail verifies that the Plugin
// interface is unaffected by name propagation: the fake plugin in this
// harness observes only the email string passed to Check, proving the
// framework attaches First/Last to the Result AFTER Check returns rather
// than threading names into the Plugin contract. No per-service checker
// needs to know about names.
func TestEnumerateWithPlugin_PluginReceivesOnlyEmail(t *testing.T) {
	t.Parallel()
	p := &recordingPlugin{name: "recording-oracle", exists: true}

	targets := []Target{
		{Email: "dana@example.com", First: "Dana", Last: "Diaz"},
		{Email: "erin@example.com"},
	}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Targets: targets,
		Threads: 2,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err)
	require.Len(t, results, 2)

	p.mu.Lock()
	checked := append([]string(nil), p.checked...)
	p.mu.Unlock()

	assert.ElementsMatch(t, []string{"dana@example.com", "erin@example.com"}, checked,
		"plugin must observe exactly the target emails and nothing else — the name path is additive")
}

// TestEnumerateWithPlugin_ErrorPathPreservesName verifies that name-stamping
// survives the error path: a Target whose Check returns a service error
// still gets First/Last on its Result. The name is a property of the
// address being checked, not of the check outcome.
func TestEnumerateWithPlugin_ErrorPathPreservesName(t *testing.T) {
	t.Parallel()
	p := &erroringPlugin{name: "erroring-oracle"}

	results, err := EnumerateWithPlugin(context.Background(), &Config{
		Targets: []Target{{Email: "failing@example.com", First: "Frank", Last: "Foster"}},
		Threads: 1,
		Timeout: 5 * time.Second,
	}, p)

	require.NoError(t, err, "EnumerateWithPlugin itself must not error for a per-check service error")
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error, "result must carry the service error")
	assert.Equal(t, "Frank", results[0].First, "name must be stamped even when the check errored")
	assert.Equal(t, "Foster", results[0].Last, "name must be stamped even when the check errored")
}
