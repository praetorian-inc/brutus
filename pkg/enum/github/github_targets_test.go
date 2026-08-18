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

// RED-phase tests for EnumerateTargetsWith, the Target-accepting sibling of
// EnumerateWith. These tests assert that names travel with their originating
// enum.Target all the way through to the Result that address produced,
// correlated by email (never by index/order, since the worker pool is
// concurrent) -- mirroring pkg/enum/gravatar/gravatar_targets_test.go.
//
// github carries one structural asymmetry the other four migrated/migrating
// packages do not: establishSession runs ONCE, synchronously, before the
// worker pool, and its own error branch has ALWAYS filled every slot
// (existence.go:74-81), migration or not. That has a direct consequence for
// how the abort-path behavior change (PLAN.md Part 0.1, 4.5) is observed
// here: an already-canceled top-level context never reaches the pool's own
// per-email `<-ctx.Done()` guard for github, because establishSession's very
// first outbound HTTP call fails immediately on an already-Done context
// (verified empirically: http.Client.Do on an already-canceled ctx returns
// "context canceled" without a round trip) and the session-failure branch
// takes over -- indistinguishable from a 403-blocked join page. See
// TestGithubEnumerateTargetsWith_SessionFailureFillsEverySlotStamped for that
// (already-correct, unaffected-by-this-PR) path, and see
// TestGithubEnumerateWith_CanceledContextNowRecordsEverySlot's doc comment
// for how the pool's OWN guard is exercised instead.
//
// EnumerateTargetsWith, worker() and newError do not exist yet on
// *Enumerator; this file is expected to fail to compile until they are added
// to existence.go (PLAN.md Part 2.5).
package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// TestGithubEnumerateTargetsWith_NamesRideOnResult
// Core test: 3 targets with distinct names against a stub that reports
// existence per the configured status map. Each returned Result must carry
// the name of the target that produced it, correlated by email. An
// implementation that stamps every Result with the first target's name fails
// this test.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_NamesRideOnResult(t *testing.T) {
	t.Parallel()

	statusFor := map[string]int{
		"exists@example.com": http.StatusUnprocessableEntity, // 422 -> Exists=true
	}
	webSrv := newWebServer(t, "csrf-names-ride", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	targets := []enum.Target{
		{Email: "exists@example.com", First: "john", Last: "smith"},
		{Email: "notexists1@example.com", First: "david", Last: "smith"},
		{Email: "notexists2@example.com", First: "michael", Last: "smith"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets), "one Result per Target")

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		assert.NoError(t, r.Error, "%q must succeed against the stub", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q must match its own Target, not another target's", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must match its own Target, not another target's", tgt.Email)
	}
	assert.True(t, byEmail["exists@example.com"].Exists, "the 422-mapped email must be reported as existing")
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateTargetsWith_NamelessTargetStaysNameless
// A Target with no name (address supplied by the operator, not generated)
// must yield First=="" && Last=="". The library must never invent a name.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-nameless", map[string]int{})
	e := newTestEnumerator(t, webSrv, nil, "")

	targets := []enum.Target{{Email: "supplied@example.com"}}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateWith_StillWorksAndYieldsEmptyNames
// Pins that the existing EnumerateWith([]string) entry point is unaffected by
// the refactor: it still returns correct results, and since bare addresses
// carry no name, First/Last must be empty.
// ---------------------------------------------------------------------------

func TestGithubEnumerateWith_StillWorksAndYieldsEmptyNames(t *testing.T) {
	t.Parallel()

	statusFor := map[string]int{
		"exists@example.com": http.StatusUnprocessableEntity,
	}
	webSrv := newWebServer(t, "csrf-still-works", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	emails := []string{"exists@example.com", "notexists1@example.com", "notexists2@example.com"}
	results := e.EnumerateWith(context.Background(), emails, 3, 0, 0, nil)
	require.Len(t, results, len(emails))

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, email := range emails {
		r, ok := byEmail[email]
		require.True(t, ok, "result for %q must be present", email)
		assert.NoError(t, r.Error, "%q must succeed against the stub", email)
		assert.Empty(t, r.First, "EnumerateWith must never invent a name")
		assert.Empty(t, r.Last, "EnumerateWith must never invent a name")
	}
	assert.True(t, byEmail["exists@example.com"].Exists, "the 422-mapped email must be reported as existing")
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateTargetsWith_NamesSurviveErrorPath
// A name is a property of the address, not of the check outcome. Drive a
// Result whose Error is non-nil (an unmapped-status response from the
// validity endpoint, mirroring postValidity's "default: unexpected status"
// branch) and assert the name is still stamped.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_NamesSurviveErrorPath(t *testing.T) {
	t.Parallel()

	const failingEmail = "failing-target@example.com"
	statusFor := map[string]int{
		failingEmail: http.StatusTeapot, // unmapped status -> postValidity error
	}
	webSrv := newWebServer(t, "csrf-error-path", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	targets := []enum.Target{
		{Email: failingEmail, First: "erin", Last: "fail"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, failingEmail, r.Email)
	require.Error(t, r.Error, "an unexpected validity-endpoint status must surface as a genuine checkEmail error")
	assert.Equal(t, "erin", r.First, "name must survive even when the probe errors")
	assert.Equal(t, "fail", r.Last, "name must survive even when the probe errors")
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateTargetsWith_MixedNamedAndUnnamed
// A single batch containing both named and unnamed targets: each Result must
// get exactly its own target's name, or empty for the unnamed ones.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-mixed", map[string]int{})
	e := newTestEnumerator(t, webSrv, nil, "")

	targets := []enum.Target{
		{Email: "named1@example.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@example.com"},
		{Email: "named2@example.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@example.com"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets))

	byEmail := make(map[string]Result, len(results))
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
// TestGithubEnumerateTargetsWith_EveryTargetSlotFilled
// len(results) == len(targets) and every target is present even when some
// probes fail. Completion order is not asserted (the worker pool is
// concurrent); correlation is by email only.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_EveryTargetSlotFilled(t *testing.T) {
	t.Parallel()

	const failingEmail = "failing-slot@example.com"
	statusFor := map[string]int{
		"exists-slot@example.com": http.StatusUnprocessableEntity,
		failingEmail:              http.StatusTeapot,
	}
	webSrv := newWebServer(t, "csrf-every-slot", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	targets := []enum.Target{
		{Email: "exists-slot@example.com", First: "carl", Last: "one"},
		{Email: failingEmail, First: "dana", Last: "two"},
		{Email: "notexists-slot@example.com", First: "ella", Last: "three"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets), "one result per target regardless of probe failures")

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "no dropped slot for %q", tgt.Email)
		assert.Equal(t, tgt.First, r.First)
		assert.Equal(t, tgt.Last, r.Last)
	}

	// Confirm the engineered failure actually failed and the others didn't,
	// proving this test exercises a genuinely mixed batch.
	assert.Error(t, byEmail[failingEmail].Error)
	assert.NoError(t, byEmail["exists-slot@example.com"].Error)
	assert.NoError(t, byEmail["notexists-slot@example.com"].Error)
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateTargetsWith_SessionFailureFillsEverySlotStamped
//
// github's pre-pool gate: if establishSession fails, every Target is
// returned carrying that error WITHOUT any worker ever running (PLAN.md Part
// 2.5). This is already correct today (existence.go:74-81 fills every slot
// on the pre-migration EnumerateWith too) and stays correct after the
// migration -- but it is the one path unique to github among the three
// packages this PR migrates, so it gets its own dedicated test rather than
// being folded into the generic shape above (PLAN.md Part 3.3's "github
// only" row).
//
// /join always returns 403 (mirrors TestSession_403ExhaustsRetries), so
// establishSession exhausts its retries and returns a non-nil error before
// the worker pool is ever constructed. Named targets must still come back
// stamped with their own name -- proving EnumerateTargetsWith's session-gate
// branch calls StampName (or an equivalent inline assignment) per target,
// not just newError.
// ---------------------------------------------------------------------------

func TestGithubEnumerateTargetsWith_SessionFailureFillsEverySlotStamped(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")
	e.existenceMaxRetries = 1

	targets := []enum.Target{
		{Email: "alice@example.com", First: "alice", Last: "anderson"},
		{Email: "bob@example.com", First: "bob", Last: "brown"},
	}

	var mu sync.Mutex
	var cbResults []Result
	results := e.EnumerateTargetsWith(context.Background(), targets, 2, 0, 0, func(r Result) {
		mu.Lock()
		cbResults = append(cbResults, r)
		mu.Unlock()
	})

	require.Len(t, results, len(targets), "every slot must be filled by the session-failure branch")

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}
	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		require.Error(t, r.Error, "session establishment failure must surface as an error for %q", tgt.Email)
		assert.Contains(t, r.Error.Error(), "join page returned HTTP 403",
			"error for %q must mention the join page HTTP status", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q must be stamped even on the session-failure path", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must be stamped even on the session-failure path", tgt.Email)
	}

	assert.Len(t, cbResults, len(targets), "onResult must fire exactly once per target on the session-failure path too")
}

// ---------------------------------------------------------------------------
// TestGithubEnumerateWith_CanceledContextNowRecordsEverySlot
//
// THE explicit before/after test for github's abort-path behavior change
// (PLAN.md Part 0.1, 2.5, 4.5), asserted through the unchanged
// EnumerateWith([]string) entry point -- the one cmd/brutus actually calls
// (cmd_enum_github.go:215) and therefore where the change is observable.
//
// Unlike gravatar and teams, github cannot demonstrate this with a context
// canceled BEFORE the call: establishSession runs first and its own error
// branch has ALWAYS filled every slot (existence.go:74-81), so an
// already-Done context just looks like any other session failure -- proven
// by construction (an already-canceled ctx makes http.Client.Do return
// "context canceled" with no round trip at all) and already covered by
// TestGithubEnumerateTargetsWith_SessionFailureFillsEverySlotStamped above.
// That path is NOT the bug this PR fixes and was never silently dropped.
//
// The actual bug is the pool's OWN per-email `<-ctx.Done()` guard
// (existence.go:110-114), which only matters once a session already exists.
// To reach it, the context must be canceled AFTER establishSession succeeds
// but before later targets' goroutines run their guard. This is done
// deterministically -- no wall-clock race -- mirroring the existing
// TestReveal_DeletesEvenWhenContextCancelled idiom (github_test.go:535):
// e.sleep is overridden to cancel ctx and return context.Canceled.
//
// emails[0] is mapped to HTTP 429, forcing its postValidity retry to call
// e.sleep (and so cancel ctx) before any later email's goroutine starts --
// guaranteed by threads=1, which serializes worker goroutines one at a time
// via errgroup's semaphore (g.Go blocks the submitting loop until a slot
// frees), so emails[1] and emails[2] do not begin until emails[0]'s goroutine
// has already returned. By the time emails[1]/emails[2] start, ctx is
// already Done, so their `select { case <-ctx.Done(): ... }` guard fires
// deterministically -- this is exactly the branch that used to `return nil`
// with no record call at all.
// ---------------------------------------------------------------------------

func TestGithubEnumerateWith_CanceledContextNowRecordsEverySlot(t *testing.T) {
	t.Parallel()

	emails := []string{"first@example.com", "second@example.com", "third@example.com"}

	statusFor := map[string]int{
		emails[0]: http.StatusTooManyRequests, // forces a retry -> e.sleep
	}
	webSrv := newWebServer(t, "csrf-cancel-mid-run", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	ctx, cancel := context.WithCancel(context.Background())
	e.sleep = func(_ context.Context, _ time.Duration) error {
		cancel()
		return context.Canceled
	}

	var mu sync.Mutex
	var cbResults []Result
	results := e.EnumerateWith(ctx, emails, 1, 0, 0, func(r Result) {
		mu.Lock()
		cbResults = append(cbResults, r)
		mu.Unlock()
	})

	require.Len(t, results, len(emails), "every slot must be filled even when ctx is canceled mid-run")
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email, "results[%d].Email must be set, not a dropped zero-value slot", i)
		assert.Error(t, r.Error, "results[%d] must carry an error, not be silently dropped", i)
	}

	// emails[1] and emails[2] must specifically carry the ctx-cancellation
	// error from the pool's own <-ctx.Done() guard -- the exact path that
	// used to drop the result entirely.
	assert.True(t, errors.Is(results[1].Error, context.Canceled),
		"results[1] must carry context.Canceled from the pool's own ctx.Done() guard")
	assert.True(t, errors.Is(results[2].Error, context.Canceled),
		"results[2] must carry context.Canceled from the pool's own ctx.Done() guard")

	assert.Len(t, cbResults, len(emails), "onResult must fire exactly once per email, even for the formerly-dropped slots")
}
