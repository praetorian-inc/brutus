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

package github

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// pushCommit: HTTP 409 conflict retries
//
// A REUSED reveal repo (SetRevealRepo) can have two runs pushing to the same
// branch head at once; GitHub answers the losing writer with HTTP 409 rather
// than serializing it. These tests exercise pushCommit's 409 handling: it
// retries with a bounded, independent budget (maxConflictRetries) and a
// jittered backoff (conflictBackoff), re-deriving a fresh file name via
// e.newName() on each retry rather than replaying the rejected write. They
// build on the newRevealServer/revealRecorder/newPersistentEnumerator helpers
// from persistent_repo_test.go, extended with revealServerOpts.pushStatuses so
// the PUT .../contents/... route can answer with a scripted status sequence.
// ---------------------------------------------------------------------------

// counterName returns a newName replacement that yields a distinct value on
// every call. newTestEnumerator (via newPersistentEnumerator) wires
// e.newName = deterministicName, which returns the SAME constant on every
// call — adequate for tests that only need A name, but it would silently
// make a conflict retry replay the identical file path instead of a fresh
// one. Tests asserting that the retry actually re-derives the name must
// install this instead.
func counterName() func() string {
	var n atomic.Int64
	return func() string {
		return fmt.Sprintf("file-%d", n.Add(1))
	}
}

// TestPushCommit_ConflictThenSuccess covers the base case: the first push
// attempt is rejected with HTTP 409, the retry succeeds, and RevealWith
// returns normally. The retry must have used a DIFFERENT content path than
// the rejected attempt — that is what makes it a fresh commit rather than a
// replay of the losing write.
func TestPushCommit_ConflictThenSuccess(t *testing.T) {
	t.Parallel()

	const token = "ghp-conflict-then-success"
	const repo = "guard-osint-reveal"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		pushStatuses:     []int{http.StatusConflict, http.StatusCreated},
		commitPages: [][]fakeCommit{
			{{email: "alice@example.com", login: "alice-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, repo)
	e.newName = counterName()

	mapping, err := e.RevealWith(context.Background(), []string{"alice@example.com"}, nil)
	require.NoError(t, err, "a 409 followed by a 201 must not surface as an error")
	assert.Equal(t, map[string]string{"alice@example.com": "alice-gh"}, mapping,
		"the email must be committed exactly once and resolved")

	got := rec.snapshot()
	assert.Equal(t, 2, got.pushes, "the rejected attempt plus the retry that succeeded")
	require.Len(t, got.pushPaths, 2)
	assert.NotEqual(t, got.pushPaths[0], got.pushPaths[1],
		"the retry must push a fresh file (via e.newName()), not replay the rejected path")
}

// TestPushCommit_ConflictBudgetExhausted covers the bound: when every push
// attempt is rejected with HTTP 409, RevealWith must fail naming HTTP 409
// rather than looping forever, after exactly maxConflictRetries retries on
// top of the initial attempt.
func TestPushCommit_ConflictBudgetExhausted(t *testing.T) {
	t.Parallel()

	const token = "ghp-conflict-exhausted"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		pushStatuses:     []int{http.StatusConflict}, // every attempt conflicts
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"bob@example.com"}, nil)
	require.Error(t, err, "an exhausted conflict budget must surface as an error")
	assert.Contains(t, err.Error(), "409")

	got := rec.snapshot()
	assert.Equal(t, maxConflictRetries+1, got.pushes,
		"bounded: the initial attempt plus exactly maxConflictRetries retries, no infinite loop")
}

// TestPushCommit_IndependentRetryBudgets verifies the 429 and 409 retry
// counters are independent: a run that alternates between the two, staying
// under EACH budget individually, must still succeed even though the
// combined attempt count exceeds either budget alone.
func TestPushCommit_IndependentRetryBudgets(t *testing.T) {
	t.Parallel()

	const token = "ghp-independent-budgets"

	// 3 rate-limit responses and 3 conflict responses interleaved, both counts
	// individually under maxRateLimitRetries and maxConflictRetries (5 each) but
	// their SUM (6) over a shared budget of 5. A shared-budget implementation
	// would therefore fail this sequence, whereas the 2+2 (4 total) sequence
	// this test used before would incorrectly succeed under a shared budget of 5
	// too — unable to actually distinguish independent counters from a shared
	// one. This sequence can.
	statuses := []int{
		http.StatusTooManyRequests,
		http.StatusConflict,
		http.StatusTooManyRequests,
		http.StatusConflict,
		http.StatusTooManyRequests,
		http.StatusConflict,
		http.StatusCreated,
	}
	require.Less(t, 3, maxRateLimitRetries, "test assumes 3 429s stays under the rate-limit budget")
	require.Less(t, 3, maxConflictRetries, "test assumes 3 409s stays under the conflict budget")

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		pushStatuses:     statuses,
		commitPages: [][]fakeCommit{
			{{email: "carol@example.com", login: "carol-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"carol@example.com"}, nil)
	require.NoError(t, err, "each retry type stayed under its own budget, so the push must succeed")
	assert.Equal(t, map[string]string{"carol@example.com": "carol-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, len(statuses), got.pushes,
		"every scripted response must have been consumed by the retry loop")
}

// TestConflictBackoff_BoundsAndJitter pins conflictBackoff's shape: for every
// attempt 1..maxConflictRetries the result must grow with attempt and stay
// within [base*attempt, base*attempt*1.5] (the documented up-to-50% jitter).
// Because the jitter is randomized, the bounds are asserted over many samples
// rather than an exact value, and at least two distinct samples are required
// to prove jitter is actually applied rather than a fixed value in disguise.
func TestConflictBackoff_BoundsAndJitter(t *testing.T) {
	t.Parallel()

	const samples = 200

	for attempt := 1; attempt <= maxConflictRetries; attempt++ {
		base := conflictBackoffBase * time.Duration(attempt)
		lower := base
		upper := base + base/2

		seen := make(map[time.Duration]struct{}, samples)
		for i := 0; i < samples; i++ {
			got := conflictBackoff(attempt)
			assert.GreaterOrEqual(t, got, lower,
				"attempt %d: backoff must not fall below conflictBackoffBase*attempt", attempt)
			assert.LessOrEqual(t, got, upper,
				"attempt %d: backoff must not exceed conflictBackoffBase*attempt*1.5", attempt)
			seen[got] = struct{}{}
		}
		assert.Greater(t, len(seen), 1,
			"attempt %d: jitter must vary the result across samples, not return a fixed value", attempt)
	}
}

// TestPushCommit_ConflictCancellationPropagates verifies that a context
// canceled during the conflict backoff wait aborts the retry loop with the
// context's error, rather than spinning or swallowing the cancellation.
func TestPushCommit_ConflictCancellationPropagates(t *testing.T) {
	t.Parallel()

	const token = "ghp-conflict-cancel"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		pushStatuses:     []int{http.StatusConflict}, // every attempt conflicts
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Simulate cancellation arriving WHILE pushCommit is waiting out the
	// conflict backoff: e.sleep stands in for that wait (see newTestEnumerator),
	// so canceling from inside it and returning ctx.Err() reproduces exactly
	// what the real sleepCtx would return had ctx been canceled mid-wait.
	e.sleep = func(_ context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}

	_, err := e.RevealWith(ctx, []string{"erin@example.com"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "the context's own error must propagate, not a wrapped or generic one")

	got := rec.snapshot()
	assert.Equal(t, 1, got.pushes,
		"cancellation during the wait must stop the loop immediately, not spin for more attempts")
}
