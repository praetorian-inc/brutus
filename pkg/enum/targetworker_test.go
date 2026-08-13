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

// RED-phase tests for the shared enum.TargetWorker pool (10T-535, PR 1 of 3).
// TargetWorker does not exist yet; this file is expected to fail to compile
// until pkg/enum/targetworker.go adds it (PLAN.md Part 1). See PLAN.md
// Part 3.2 for the full worker-level test-plan rationale (tests W1-W16
// below); this is the ONE place these properties are tested -- google and
// microsoft365's own target tests are the regression net for the migration,
// not a place to re-test the pool.
//
// fakeResult is a local stand-in for the five real result types (google's
// Result, microsoft365's Result, etc.) so these tests exercise Run directly,
// independent of any enumerator package. Sentinel proves NewError -- not a
// generic zero value -- built a failure result: if Run ever constructed R
// without calling the hook, Sentinel would come back empty and the relevant
// assertions would fail.
package enum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResult stands in for the five real result types.
type fakeResult struct {
	Email       string
	First, Last string
	Err         error
	Sentinel    string
}

// fakeWorker builds a TargetWorker[fakeResult] configured the way every real
// package configures one: a Label, the supplied Check, a NewError that marks
// itself with Sentinel so tests can prove the worker used the hook rather
// than a zero value, and a StampName that copies the Target's name.
func fakeWorker(check func(context.Context, string) fakeResult) TargetWorker[fakeResult] {
	return TargetWorker[fakeResult]{
		Label: "fake enum",
		Check: check,
		NewError: func(email string, err error) fakeResult {
			return fakeResult{Email: email, Err: err, Sentinel: "from-newerror"}
		},
		StampName: func(r *fakeResult, t Target) { r.First, r.Last = t.First, t.Last },
	}
}

// ---------------------------------------------------------------------------
// W1 - TestRun_ReturnsInputOrder
// ---------------------------------------------------------------------------

func TestRun_ReturnsInputOrder(t *testing.T) {
	t.Parallel()

	const n = 6
	targets := make([]Target, n)
	sleepFor := make(map[string]time.Duration, n)
	for i := 0; i < n; i++ {
		email := fmt.Sprintf("t%d@x.com", i)
		targets[i] = Target{Email: email}
		// Earlier indices sleep longer, so completion order is the reverse
		// of input order -- the ordering assertion below cannot pass by
		// accident of scheduling.
		sleepFor[email] = time.Duration(n-i) * 5 * time.Millisecond
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		time.Sleep(sleepFor[email])
		return fakeResult{Email: email}
	})

	results := w.Run(context.Background(), targets, 8, 0, 0, nil)
	require.Len(t, results, n)
	for i, tgt := range targets {
		assert.Equal(t, tgt.Email, results[i].Email,
			"results[%d].Email must match targets[%d].Email regardless of completion order", i, i)
	}
}

// ---------------------------------------------------------------------------
// W2 - TestRun_EverySlotFilledAndCallbackOncePerTarget
// ---------------------------------------------------------------------------

func TestRun_EverySlotFilledAndCallbackOncePerTarget(t *testing.T) {
	t.Parallel()

	const n = 8
	targets := make([]Target, n)
	shouldFail := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		email := fmt.Sprintf("u%d@x.com", i)
		targets[i] = Target{Email: email}
		shouldFail[email] = i%2 == 1
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		if shouldFail[email] {
			return fakeResult{Email: email, Err: errors.New("probe failed")}
		}
		return fakeResult{Email: email}
	})

	var mu sync.Mutex
	seen := make(map[string]int, n)
	results := w.Run(context.Background(), targets, 4, 0, 0, func(r fakeResult) {
		mu.Lock()
		seen[r.Email]++
		mu.Unlock()
	})

	require.Len(t, results, n)
	for i, tgt := range targets {
		r := results[i]
		assert.Equal(t, tgt.Email, r.Email, "results[%d] must not be a dropped zero-value slot", i)
		assert.NotEmpty(t, r.Email, "results[%d] must never be a zero-value fakeResult", i)
	}

	assert.Len(t, seen, n, "callback must have fired for every target's email")
	for email, count := range seen {
		assert.Equal(t, 1, count, "callback must fire exactly once for %q", email)
	}
}

// ---------------------------------------------------------------------------
// W3 - TestRun_StampsOriginatingTargetName
// ---------------------------------------------------------------------------

func TestRun_StampsOriginatingTargetName(t *testing.T) {
	t.Parallel()

	targets := []Target{
		{Email: "a@x.com", First: "anna", Last: "lee"},
		{Email: "b@x.com", First: "bob", Last: "wu"},
		{Email: "c@x.com", First: "carl", Last: "chen"},
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	results := w.Run(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets))

	byEmail := make(map[string]fakeResult, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q must match its own target, never a neighbour's", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must match its own target, never a neighbour's", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// W4 - TestRun_NamelessTargetStaysNameless
// ---------------------------------------------------------------------------

func TestRun_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()

	targets := []Target{{Email: "supplied@x.com"}}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	results := w.Run(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// W5 - TestRun_MixedNamedAndUnnamed
// ---------------------------------------------------------------------------

func TestRun_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()

	targets := []Target{
		{Email: "named1@x.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@x.com"},
		{Email: "named2@x.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@x.com"},
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	results := w.Run(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets))

	byEmail := make(map[string]fakeResult, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// W6 - TestRun_NameSurvivesEveryAbortPath
//
// Table of the four paths that reach record() WITHOUT a normal Check return:
// an already-canceled context, a rate-limiter error, cancellation during
// jitter, and panic recovery. Every one must (a) carry the originating
// target's name and (b) carry Sentinel == "from-newerror", proving the
// result came from the NewError hook and not a generic zero value.
// ---------------------------------------------------------------------------

func TestRun_NameSurvivesEveryAbortPath(t *testing.T) {
	t.Run("already-canceled context", func(t *testing.T) {
		t.Parallel()

		targets := []Target{{Email: "one@x.com", First: "gwen", Last: "alpha"}}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		var checkCalls atomic.Int32
		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			checkCalls.Add(1)
			return fakeResult{Email: email}
		})

		results := w.Run(ctx, targets, 1, 0, 0, nil)
		require.Len(t, results, 1)

		r := results[0]
		assert.Equal(t, int32(0), checkCalls.Load(), "Check must not be called when ctx is already canceled")
		assert.Equal(t, "from-newerror", r.Sentinel, "already-canceled path must go through NewError, not a zero value")
		require.Error(t, r.Err)
		assert.Equal(t, "gwen", r.First, "name must survive the already-canceled-context path")
		assert.Equal(t, "alpha", r.Last)
	})

	t.Run("rate limiter error", func(t *testing.T) {
		t.Parallel()

		targets := []Target{
			{Email: "one@x.com", First: "gwen", Last: "alpha"},
			{Email: "two@x.com", First: "hank", Last: "beta"},
		}

		// A short deadline plus an extremely low rate: the token bucket
		// starts with one burst token, so whichever goroutine claims it
		// proceeds immediately; the other must wait far longer than the
		// remaining deadline, and rate.Limiter.Wait returns that error
		// immediately rather than actually waiting.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			return fakeResult{Email: email}
		})

		results := w.Run(ctx, targets, 2, 0.001, 0, nil)
		require.Len(t, results, len(targets))

		byEmail := make(map[string]fakeResult, len(results))
		for _, r := range results {
			byEmail[r.Email] = r
		}

		var limited *fakeResult
		for _, tgt := range targets {
			r := byEmail[tgt.Email]
			if r.Sentinel == "from-newerror" {
				rc := r
				limited = &rc
				break
			}
		}
		require.NotNil(t, limited, "at least one target must be rejected by the rate limiter within the short deadline")
		require.Error(t, limited.Err)

		for _, tgt := range targets {
			if tgt.Email == limited.Email {
				assert.Equal(t, tgt.First, limited.First, "name must survive the rate-limiter-error path")
				assert.Equal(t, tgt.Last, limited.Last, "name must survive the rate-limiter-error path")
			}
		}
	})

	t.Run("jitter cancel", func(t *testing.T) {
		t.Parallel()

		targets := []Target{{Email: "jit@x.com", First: "iris", Last: "gamma"}}

		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(10*time.Millisecond, cancel)

		var checkCalls atomic.Int32
		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			checkCalls.Add(1)
			return fakeResult{Email: email}
		})

		// rateLimit high enough that the single request's Wait succeeds
		// immediately (burst token available); jitter large enough that the
		// random delay is very unlikely to elapse before the 10ms cancel.
		results := w.Run(ctx, targets, 1, 1000, 2*time.Second, nil)
		require.Len(t, results, 1)

		r := results[0]
		assert.Equal(t, int32(0), checkCalls.Load(), "Check must not be called when ctx is canceled during jitter")
		assert.Equal(t, "from-newerror", r.Sentinel, "jitter-cancel path must go through NewError, not a zero value")
		require.Error(t, r.Err)
		assert.Equal(t, "iris", r.First, "name must survive cancellation during jitter")
		assert.Equal(t, "gamma", r.Last)
	})

	// Deliberately NOT t.Parallel(): this subtest swaps the package-level
	// os.Stderr (see TestRun_PanicInCheckIsIsolated below, which does the
	// same). Running both concurrently with each other would race on that
	// global under -race.
	t.Run("panic in Check", func(t *testing.T) {
		targets := []Target{{Email: "panic@x.com", First: "jill", Last: "delta"}}

		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			panic("boom")
		})

		origStderr := os.Stderr
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		require.NoError(t, err)
		os.Stderr = devNull
		results := w.Run(context.Background(), targets, 1, 0, 0, nil)
		os.Stderr = origStderr
		require.NoError(t, devNull.Close())

		require.Len(t, results, 1)
		r := results[0]
		assert.Equal(t, "from-newerror", r.Sentinel, "panic path must go through NewError, not a zero value")
		require.Error(t, r.Err)
		assert.Equal(t, "jill", r.First, "name must survive a panic inside Check")
		assert.Equal(t, "delta", r.Last)
	})
}

// ---------------------------------------------------------------------------
// W7 - TestRun_CanceledContextRecordsEveryTarget
// ---------------------------------------------------------------------------

func TestRun_CanceledContextRecordsEveryTarget(t *testing.T) {
	t.Parallel()

	targets := []Target{
		{Email: "one@x.com"},
		{Email: "two@x.com"},
		{Email: "three@x.com"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var checkCalls atomic.Int32
	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		checkCalls.Add(1)
		return fakeResult{Email: email}
	})

	var mu sync.Mutex
	var cbEmails []string
	results := w.Run(ctx, targets, 4, 0, 0, func(r fakeResult) {
		mu.Lock()
		cbEmails = append(cbEmails, r.Email)
		mu.Unlock()
	})

	require.Len(t, results, len(targets))
	assert.Equal(t, int32(0), checkCalls.Load(), "Check must never be called on an already-canceled context")
	for i, tgt := range targets {
		assert.Equal(t, tgt.Email, results[i].Email, "results[%d].Email must be set (input order preserved)", i)
		require.Error(t, results[i].Err)
		assert.True(t, errors.Is(results[i].Err, context.Canceled), "results[%d].Err must be context.Canceled", i)
	}
	assert.Len(t, cbEmails, len(targets), "onResult must fire exactly once per target on the canceled-context path")
}

// ---------------------------------------------------------------------------
// W8 - TestRun_ZeroOrNegativeThreadsDoesNotHang
// ---------------------------------------------------------------------------

func TestRun_ZeroOrNegativeThreadsDoesNotHang(t *testing.T) {
	for _, threads := range []int{0, -1} {
		t.Run(fmt.Sprintf("threads=%d", threads), func(t *testing.T) {
			t.Parallel()

			targets := []Target{{Email: "a@x.com"}, {Email: "b@x.com"}, {Email: "c@x.com"}}

			w := fakeWorker(func(ctx context.Context, email string) fakeResult {
				return fakeResult{Email: email}
			})

			done := make(chan []fakeResult, 1)
			go func() {
				done <- w.Run(context.Background(), targets, threads, 0, 0, nil)
			}()

			select {
			case results := <-done:
				require.Len(t, results, len(targets))
				byEmail := make(map[string]fakeResult, len(results))
				for _, r := range results {
					byEmail[r.Email] = r
				}
				for _, tgt := range targets {
					_, ok := byEmail[tgt.Email]
					assert.True(t, ok, "result for %q must be present", tgt.Email)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Run did not return within 2s for threads=%d; a bad clamp (e.g. SetLimit(0)) would hang forever", threads)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// W9 - TestRun_BoundsConcurrency
// ---------------------------------------------------------------------------

func TestRun_BoundsConcurrency(t *testing.T) {
	t.Parallel()

	const threads = 4
	const n = 40

	targets := make([]Target, n)
	for i := 0; i < n; i++ {
		targets[i] = Target{Email: fmt.Sprintf("c%d@x.com", i)}
	}

	var current, peak atomic.Int32
	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		c := current.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		current.Add(-1)
		return fakeResult{Email: email}
	})

	results := w.Run(context.Background(), targets, threads, 0, 0, nil)
	require.Len(t, results, n)
	assert.LessOrEqual(t, peak.Load(), int32(threads), "peak concurrent Check calls must not exceed threads")
}

// ---------------------------------------------------------------------------
// W10 - TestRun_RateLimitPaces
// ---------------------------------------------------------------------------

func TestRun_RateLimitPaces(t *testing.T) {
	t.Parallel()

	const n = 5
	targets := make([]Target, n)
	for i := 0; i < n; i++ {
		targets[i] = Target{Email: fmt.Sprintf("r%d@x.com", i)}
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	start := time.Now()
	results := w.Run(context.Background(), targets, n, 20, 0, nil)
	elapsed := time.Since(start)

	require.Len(t, results, n)
	// 5 requests at 20/s with burst 1: the first is free, the remaining 4
	// must each wait ~1/20s, so total elapsed should be at least ~4/20s
	// (200ms). Use a slightly relaxed floor to absorb scheduler jitter.
	assert.GreaterOrEqual(t, elapsed, 190*time.Millisecond, "rate limiting must pace requests to roughly the configured rate")
}

// ---------------------------------------------------------------------------
// W11 - TestRun_JitterIgnoredWithoutRateLimit
// ---------------------------------------------------------------------------

func TestRun_JitterIgnoredWithoutRateLimit(t *testing.T) {
	t.Parallel()

	targets := []Target{{Email: "a@x.com"}, {Email: "b@x.com"}, {Email: "c@x.com"}}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	start := time.Now()
	results := w.Run(context.Background(), targets, 3, 0, 2*time.Second, nil)
	elapsed := time.Since(start)

	require.Len(t, results, len(targets))
	assert.Less(t, elapsed, 500*time.Millisecond,
		"jitter must be ignored entirely when rateLimit is 0 -- jitter lives inside the rate-limiter branch, "+
			"a 2s jitter here must not slow this run down")
}

// ---------------------------------------------------------------------------
// W12 - TestRun_NilCallbackIsSafe
// ---------------------------------------------------------------------------

func TestRun_NilCallbackIsSafe(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		targets := []Target{{Email: "a@x.com"}}
		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			return fakeResult{Email: email}
		})

		var results []fakeResult
		assert.NotPanics(t, func() {
			results = w.Run(context.Background(), targets, 1, 0, 0, nil)
		})
		require.Len(t, results, 1)
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()

		targets := []Target{{Email: "b@x.com"}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		w := fakeWorker(func(ctx context.Context, email string) fakeResult {
			return fakeResult{Email: email}
		})

		var results []fakeResult
		assert.NotPanics(t, func() {
			results = w.Run(ctx, targets, 1, 0, 0, nil)
		})
		require.Len(t, results, 1)
	})
}

// ---------------------------------------------------------------------------
// W13 - TestRun_CallbackIsSerialized
// ---------------------------------------------------------------------------

func TestRun_CallbackIsSerialized(t *testing.T) {
	t.Parallel()

	const n = 50
	targets := make([]Target, n)
	for i := 0; i < n; i++ {
		targets[i] = Target{Email: fmt.Sprintf("s%d@x.com", i)}
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		return fakeResult{Email: email}
	})

	// inCallback is deliberately unsynchronized: if onResult is ever invoked
	// concurrently with itself, a plain (non-atomic) read/write race is
	// exactly what proves the callback is not serialized under the results
	// mutex, and -race will flag the race even if the boolean logic misses it.
	var inCallback bool
	var raced atomic.Bool
	onResult := func(r fakeResult) {
		if inCallback {
			raced.Store(true)
			return
		}
		inCallback = true
		defer func() { inCallback = false }()
	}

	results := w.Run(context.Background(), targets, 8, 0, 0, onResult)
	require.Len(t, results, n)
	assert.False(t, raced.Load(), "onResult invoked concurrently: callback is not serialized under the results mutex")
}

// ---------------------------------------------------------------------------
// W14 - TestRun_PanicInCheckIsIsolated
//
// Deliberately NOT t.Parallel(): swaps the package-level os.Stderr, same
// hazard noted on the "panic in Check" subtest of TestRun_NameSurvivesEvery-
// AbortPath above.
// ---------------------------------------------------------------------------

func TestRun_PanicInCheckIsIsolated(t *testing.T) {
	targets := []Target{
		{Email: "ok1@x.com"},
		{Email: "boom@x.com"},
		{Email: "ok2@x.com"},
	}

	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		if email == "boom@x.com" {
			panic("kaboom")
		}
		return fakeResult{Email: email}
	})

	origStderr := os.Stderr
	rpipe, wpipe, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = wpipe

	results := w.Run(context.Background(), targets, 1, 0, 0, nil)

	os.Stderr = origStderr
	require.NoError(t, wpipe.Close())
	captured, err := io.ReadAll(rpipe)
	require.NoError(t, err)

	require.Len(t, results, len(targets))
	byEmail := make(map[string]fakeResult, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	panicked := byEmail["boom@x.com"]
	assert.Equal(t, "from-newerror", panicked.Sentinel, "a panic in Check must be recorded via NewError, not a zero value")
	require.Error(t, panicked.Err)
	assert.Contains(t, panicked.Err.Error(), "fake enum: panicked:",
		"Label must prefix the panic result error exactly as every real package's Label does")

	assert.NoError(t, byEmail["ok1@x.com"].Err, "a panic in one target must not affect others")
	assert.NoError(t, byEmail["ok2@x.com"].Err, "a panic in one target must not affect others")

	assert.Contains(t, string(captured), "fake enum: panic checking boom@x.com:",
		"Label must prefix the stderr diagnostic exactly as every real package's Label does")
}

// ---------------------------------------------------------------------------
// W15 - TestRun_EmptyTargets
// ---------------------------------------------------------------------------

func TestRun_EmptyTargets(t *testing.T) {
	t.Parallel()

	var checkCalls atomic.Int32
	w := fakeWorker(func(ctx context.Context, email string) fakeResult {
		checkCalls.Add(1)
		return fakeResult{Email: email}
	})

	var callbackCalls atomic.Int32
	results := w.Run(context.Background(), []Target{}, 4, 0, 0, func(r fakeResult) {
		callbackCalls.Add(1)
	})

	require.NotNil(t, results, "Run must return a non-nil (empty) slice for zero targets")
	assert.Len(t, results, 0)
	assert.Equal(t, int32(0), checkCalls.Load(), "Check must never be called when there are no targets")
	assert.Equal(t, int32(0), callbackCalls.Load(), "onResult must never fire when there are no targets")
}

// ---------------------------------------------------------------------------
// W16 - TestRun_PanicsOnMissingHooks
// ---------------------------------------------------------------------------

func TestRun_PanicsOnMissingHooks(t *testing.T) {
	base := func() TargetWorker[fakeResult] {
		return fakeWorker(func(ctx context.Context, email string) fakeResult {
			return fakeResult{Email: email}
		})
	}

	targets := []Target{{Email: "a@x.com"}}

	tests := []struct {
		name string
		mod  func(w *TargetWorker[fakeResult])
	}{
		{"nil Check", func(w *TargetWorker[fakeResult]) { w.Check = nil }},
		{"nil NewError", func(w *TargetWorker[fakeResult]) { w.NewError = nil }},
		{"nil StampName", func(w *TargetWorker[fakeResult]) { w.StampName = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := base()
			tt.mod(&w)

			assert.PanicsWithValue(t, "enum: TargetWorker requires Check, NewError and StampName", func() {
				w.Run(context.Background(), targets, 1, 0, 0, nil)
			})
		})
	}
}
