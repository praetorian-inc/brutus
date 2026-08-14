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
// concurrent) -- mirroring pkg/enum/google/google_targets_test.go.
//
// gravatar carries one asymmetry the other migrated packages do not: every
// Result also carries a Hash, computed from the normalized (lower-cased,
// trimmed) email even though Result.Email echoes the input verbatim. A
// generic "R{} + error" construction inside newError would silently drop
// Hash on every failure result. TestGravatarEnumerateTargetsWith_
// HashSurvivesFailingProbe is the dedicated regression guard for that; see
// its comment for why it is the single most valuable test in this file.
//
// EnumerateTargetsWith, worker() and newError do not exist yet on *Checker;
// this file is expected to fail to compile until they are added to
// gravatar.go (PLAN.md Part 2.3).
package gravatar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// failingEmail is the address whose Gravatar hash the target-test mock server
// answers with a genuine 500, giving CheckAccount a real (non-nil) Error to
// propagate. This is what lets these tests drive a real error path through
// EnumerateTargetsWith without inventing an injectable probe seam.
// registeredEmail (declared in gravatar_test.go, same package) is reused
// unchanged for the "exists" case.
const failingEmail = "failing-target@example.com"

// newTargetsMockServer builds an httptest.Server keyed by avatar hash, in the
// same style as newMockServer (gravatar_test.go:64 -- the package's existing
// HTTP-stubbing seam): registeredEmail's hash answers 200 (exists),
// failingEmail's hash answers 500 (a genuine CheckAccount error, same shape as
// TestCheckAccount_ServerError in gravatar_test.go), and every other hash
// 404s (not exists, no error). This is the minimal extension of the existing
// seam needed for the target tests below; no fake/injected probe is used and
// no real network call is made.
func newTargetsMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	registeredHash := HashEmail(registeredEmail)
	failingHash := HashEmail(failingEmail)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPrefix := "/avatar/"
		if !strings.HasPrefix(r.URL.Path, wantPrefix) {
			http.NotFound(w, r)
			return
		}
		hash := strings.TrimPrefix(r.URL.Path, wantPrefix)
		switch hash {
		case failingHash:
			w.WriteHeader(http.StatusInternalServerError)
		case registeredHash:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_NamesRideOnResult
// Core test: 3 targets with distinct names against a stub that reports
// existence for all of them. Each returned Result must carry the name of the
// target that produced it, correlated by email. An implementation that
// stamps every Result with the first target's name fails this test.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_NamesRideOnResult(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: registeredEmail, First: "john", Last: "smith"},
		{Email: "notexists1@example.com", First: "david", Last: "smith"},
		{Email: "notexists2@example.com", First: "michael", Last: "smith"},
	}

	results := c.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
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
	assert.True(t, byEmail[registeredEmail].Exists, "registeredEmail must be reported as existing by the stub")
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_NamelessTargetStaysNameless
// A Target with no name (address supplied by the operator, not generated)
// must yield First=="" && Last=="". The library must never invent a name.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{{Email: "supplied@example.com"}}

	results := c.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateWith_StillWorksAndYieldsEmptyNames
// Pins that the existing EnumerateWith([]string) entry point is unaffected by
// the refactor: it still returns correct results, and since bare addresses
// carry no name, First/Last must be empty.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateWith_StillWorksAndYieldsEmptyNames(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{registeredEmail, "notexists1@example.com", "notexists2@example.com"}
	results := c.EnumerateWith(context.Background(), emails, 3, 0, 0, nil)
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
	assert.True(t, byEmail[registeredEmail].Exists, "registeredEmail must be reported as existing by the stub")
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_NamesSurviveErrorPath
// A name is a property of the address, not of the check outcome. Drive a
// Result whose Error is non-nil (the mock server's 500 for failingEmail) and
// assert the name is still stamped.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_NamesSurviveErrorPath(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: failingEmail, First: "erin", Last: "fail"},
	}

	results := c.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, failingEmail, r.Email)
	require.Error(t, r.Error, "the 500 response must surface as a genuine CheckAccount error")
	assert.Equal(t, "erin", r.First, "name must survive even when the probe errors")
	assert.Equal(t, "fail", r.Last, "name must survive even when the probe errors")
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_MixedNamedAndUnnamed
// A single batch containing both named and unnamed targets: each Result must
// get exactly its own target's name, or empty for the unnamed ones.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "named1@example.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@example.com"},
		{Email: "named2@example.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@example.com"},
	}

	results := c.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
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
// TestGravatarEnumerateTargetsWith_EveryTargetSlotFilled
// len(results) == len(targets) and every target is present even when some
// probes fail. Completion order is not asserted (the worker pool is
// concurrent); correlation is by email only.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_EveryTargetSlotFilled(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: registeredEmail, First: "carl", Last: "one"},
		{Email: failingEmail, First: "dana", Last: "two"},
		{Email: "notexists@example.com", First: "ella", Last: "three"},
	}

	results := c.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
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
	assert.NoError(t, byEmail[registeredEmail].Error)
	assert.NoError(t, byEmail["notexists@example.com"].Error)
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_NamesSurviveCancelledContext
// Chokepoint test: with the context already canceled before the call, every
// goroutine takes the <-ctx.Done() early-return branch and records via
// newError WITHOUT ever calling CheckAccount. If the name stamp lived only at
// the CheckAccount call site rather than at the single funnel every outcome
// passes through, these Results would come back nameless.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_NamesSurviveCancelledContext(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "one@example.com", First: "gwen", Last: "alpha"},
		{Email: "two@example.com", First: "hank", Last: "beta"},
		{Email: "three@example.com", First: "iris", Last: "gamma"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled BEFORE the call

	results := c.EnumerateTargetsWith(ctx, targets, 1, 0, 0, nil)
	require.Len(t, results, len(targets))

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		require.Error(t, r.Error, "an already-canceled context must surface as a non-nil Error for %q", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q must survive the ctx.Done() early return", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must survive the ctx.Done() early return", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// TestGravatarEnumerateTargetsWith_HashSurvivesFailingProbe
//
// This is the single most valuable test in this file (PLAN.md Part 3.3): every
// gravatar Result -- success or failure -- carries a Hash computed from the
// normalized email, even though Result.Email echoes the input verbatim. If
// newError is written as a bare Result{Email: email, Error: err}, every
// failed probe silently loses its hash: no compile error, no other test
// failure. This test would catch exactly that regression.
//
// Two cases, both required:
//   - a genuine probe failure (mock server 500) -- Hash must survive the path
//     through CheckAccount's own error return.
//   - an already-canceled context -- this path never reaches CheckAccount at
//     all, so newError alone is responsible for the Hash on this Result. If
//     Hash is dropped, this is the case that proves it.
// ---------------------------------------------------------------------------

func TestGravatarEnumerateTargetsWith_HashSurvivesFailingProbe(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	// Case 1: a genuine probe failure (500 from the mock server).
	failTargets := []enum.Target{{Email: failingEmail, First: "hank", Last: "hash"}}
	failResults := c.EnumerateTargetsWith(context.Background(), failTargets, 1, 0, 0, nil)
	require.Len(t, failResults, 1)
	require.Error(t, failResults[0].Error, "the 500 response must surface as a genuine CheckAccount error")
	assert.Equal(t, HashEmail(failingEmail), failResults[0].Hash,
		"Hash must survive on a failing probe result -- a newError that drops Hash breaks this")

	// Case 2: an already-canceled context, which never reaches CheckAccount at
	// all and is recorded entirely by newError inside the worker.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelTargets := []enum.Target{{Email: "canceled-target@example.com", First: "iris", Last: "cancel"}}
	cancelResults := c.EnumerateTargetsWith(ctx, cancelTargets, 1, 0, 0, nil)
	require.Len(t, cancelResults, 1)
	require.Error(t, cancelResults[0].Error)
	assert.True(t, errors.Is(cancelResults[0].Error, context.Canceled))
	assert.Equal(t, HashEmail("canceled-target@example.com"), cancelResults[0].Hash,
		"Hash must survive on the ctx.Done() abort path too -- this is the path that never calls "+
			"CheckAccount, so newError is the ONLY place Hash can come from")
}
