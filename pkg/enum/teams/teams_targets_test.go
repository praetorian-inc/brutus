// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// RED-phase tests for EnumerateTargetsWith, the Target-accepting sibling of
// EnumerateWith. These tests assert that names travel with their originating
// enum.Target all the way through to the EnumResult that address produced,
// correlated by email (never by index/order, since the worker pool is
// concurrent) -- mirroring pkg/enum/gravatar/gravatar_targets_test.go.
//
// Unlike github (which gates the whole batch behind establishSession before
// the pool ever runs -- see github_targets_test.go), teams has no pre-pool
// gate: every email goes straight into the worker pool. That means an
// already-canceled top-level context reaches the pool's own per-email
// `<-ctx.Done()` guard directly, which is exactly the guard that used to
// silently drop the result (see TestTeamsEnumerateWith_
// CanceledContextNowRecordsEverySlot below -- the one genuinely NEW behavior
// this file pins).
//
// EnumerateTargetsWith, worker() and newError do not exist yet on
// *Enumerator; this file is expected to fail to compile until they are added
// to enum.go (PLAN.md Part 2.4).
package teams

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// registeredEmail is the email the target-test mock server answers with a
// corporate (8:orgid:) match; failingEmail gets a genuine unexpected-status
// error from EnumerateOne (mirrors TestEnumerateOne_ServerError500's shape);
// every other email gets an empty-array "not found" response.
const (
	registeredEmail = "exists@contoso.com"
	failingEmail    = "failing-target@contoso.com"
)

// newTargetsSearchServer builds an httptest.Server keyed by the escaped email
// in the URL path, in the same style as searchServerPerEmail
// (enum_test.go:1042 -- the package's existing HTTP-stubbing seam):
// registeredEmail answers with a corporate user (existence "yes"),
// failingEmail answers 500 (a genuine EnumerateOne error, same shape as
// TestEnumerateOne_ServerError500), and every other email answers an empty
// array (existence "no", no error). This is the minimal extension of the
// existing seam needed for the target tests below; no fake/injected probe is
// used and no real network call is made.
func newTargetsSearchServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		email := parts[len(parts)-1]

		if email == failingEmail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if email == registeredEmail {
			_, _ = w.Write([]byte(`[{"displayName":"Existing User","mri":"8:orgid:abc123"}]`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
}

// newTargetsTestEnumerator builds an Enumerator wired to srv, mirroring
// newTestEnumerator (enum_test.go:35) but for the target-test mock server's
// URL-path (not query-param) keying.
func newTargetsTestEnumerator(t *testing.T, srv *httptest.Server) *Enumerator {
	t.Helper()
	e, err := NewEnumerator("test-access-token", "", "", 5*time.Second, false)
	require.NoError(t, err)
	e.searchBaseURL = srv.URL + "/%s"
	return e
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateTargetsWith_NamesRideOnResult
// Core test: 3 targets with distinct names against a stub that reports
// existence for all of them. Each returned EnumResult must carry the name of
// the target that produced it, correlated by email. An implementation that
// stamps every EnumResult with the first target's name fails this test.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_NamesRideOnResult(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: registeredEmail, First: "john", Last: "smith"},
		{Email: "notfound1@contoso.com", First: "david", Last: "smith"},
		{Email: "notfound2@contoso.com", First: "michael", Last: "smith"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets), "one EnumResult per Target")

	byEmail := make(map[string]EnumResult, len(results))
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
	assert.Equal(t, ExistenceYes, byEmail[registeredEmail].Exists, "registeredEmail must be reported as existing by the stub")
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateTargetsWith_NamelessTargetStaysNameless
// A Target with no name (address supplied by the operator, not generated)
// must yield First=="" && Last=="". The library must never invent a name.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{{Email: "supplied@contoso.com"}}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateWith_StillWorksAndYieldsEmptyNames
// Pins that the existing EnumerateWith([]string) entry point is unaffected by
// the refactor: it still returns correct results, and since bare addresses
// carry no name, First/Last must be empty.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateWith_StillWorksAndYieldsEmptyNames(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	emails := []string{registeredEmail, "notfound1@contoso.com", "notfound2@contoso.com"}
	results := e.EnumerateWith(context.Background(), emails, 3, 0, 0, nil)
	require.Len(t, results, len(emails))

	byEmail := make(map[string]EnumResult, len(results))
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
	assert.Equal(t, ExistenceYes, byEmail[registeredEmail].Exists, "registeredEmail must be reported as existing by the stub")
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateTargetsWith_NamesSurviveErrorPath
// A name is a property of the address, not of the check outcome. Drive an
// EnumResult whose Error is non-nil (the mock server's 500 for failingEmail)
// and assert the name is still stamped.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_NamesSurviveErrorPath(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: failingEmail, First: "erin", Last: "fail"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, failingEmail, r.Email)
	require.Error(t, r.Error, "the 500 response must surface as a genuine EnumerateOne error")
	assert.Equal(t, ExistenceUnknown, r.Exists, "a failed probe must report Exists as Unknown, not the invalid empty string")
	assert.Equal(t, "erin", r.First, "name must survive even when the probe errors")
	assert.Equal(t, "fail", r.Last, "name must survive even when the probe errors")
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateTargetsWith_MixedNamedAndUnnamed
// A single batch containing both named and unnamed targets: each EnumResult
// must get exactly its own target's name, or empty for the unnamed ones.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "named1@contoso.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@contoso.com"},
		{Email: "named2@contoso.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@contoso.com"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets))

	byEmail := make(map[string]EnumResult, len(results))
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
// TestTeamsEnumerateTargetsWith_EveryTargetSlotFilled
// len(results) == len(targets) and every target is present even when some
// probes fail. Completion order is not asserted (the worker pool is
// concurrent); correlation is by email only.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_EveryTargetSlotFilled(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: registeredEmail, First: "carl", Last: "one"},
		{Email: failingEmail, First: "dana", Last: "two"},
		{Email: "notfound@contoso.com", First: "ella", Last: "three"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 4, 0, 0, nil)
	require.Len(t, results, len(targets), "one result per target regardless of probe failures")

	byEmail := make(map[string]EnumResult, len(results))
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
	assert.NoError(t, byEmail["notfound@contoso.com"].Error)
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateTargetsWith_NamesSurviveCancelledContext
//
// Chokepoint test: with the context already canceled before the call, every
// goroutine takes the <-ctx.Done() early-return branch and records via
// newError WITHOUT ever calling EnumerateOne. Unlike github (which gates the
// whole batch behind establishSession first -- see github_targets_test.go),
// teams has no pre-pool gate, so this reaches the pool's own guard directly.
// If the name stamp lived only at the EnumerateOne call site rather than at
// the single funnel every outcome passes through, these Results would come
// back nameless.
//
// This is also the RED-phase pin for the abort-path behavior change itself
// (PLAN.md Part 0.1, 2.4, 4.5): today, this early-return is a bare `return
// nil` with no record call at all, so results[i] stays the zero EnumResult
// (Email=="") and onResult never fires. See
// TestTeamsEnumerateWith_CanceledContextNowRecordsEverySlot below for the
// same behavior change asserted through the unchanged EnumerateWith(
// []string) entry point that cmd/brutus actually calls.
// ---------------------------------------------------------------------------

func TestTeamsEnumerateTargetsWith_NamesSurviveCancelledContext(t *testing.T) {
	t.Parallel()
	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "one@contoso.com", First: "gwen", Last: "alpha"},
		{Email: "two@contoso.com", First: "hank", Last: "beta"},
		{Email: "three@contoso.com", First: "iris", Last: "gamma"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled BEFORE the call

	results := e.EnumerateTargetsWith(ctx, targets, 1, 0, 0, nil)
	require.Len(t, results, len(targets), "every slot must be filled, not left as a dropped zero-value EnumResult")

	byEmail := make(map[string]EnumResult, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, tgt := range targets {
		r, ok := byEmail[tgt.Email]
		require.True(t, ok, "result for %q must be present", tgt.Email)
		require.Error(t, r.Error, "an already-canceled context must surface as a non-nil Error for %q", tgt.Email)
		assert.Equal(t, ExistenceUnknown, r.Exists, "an aborted result must report Exists as Unknown, not the invalid empty string, for %q", tgt.Email)
		assert.Equal(t, tgt.First, r.First, "First for %q must survive the ctx.Done() early return", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must survive the ctx.Done() early return", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// TestTeamsEnumerateWith_CanceledContextNowRecordsEverySlot
//
// THE explicit before/after test for teams' abort-path behavior change
// (PLAN.md Part 0.1, 2.4, 4.5), asserted through the unchanged
// EnumerateWith([]string) entry point -- the one cmd/brutus actually calls
// (cmd_enum_teams.go:471) and therefore where the change is observable.
//
// Before this PR: EnumerateWith's per-email goroutine took the
// `<-ctx.Done(): return nil` branch with NO record call at all, so an
// already-canceled context left every results[i] the zero EnumResult
// (Email=="", Exists=="" -- an invalid tri-state DerivePosture reads) and
// onResult never fired. After the migration onto enum.TargetWorker, the same
// path records via NewError (Email, Exists: ExistenceUnknown, the
// cancellation error) and fires onResult exactly once per target -- matching
// what google, microsoft365 and gravatar already did.
//
// Unlike github, teams has no pre-pool session gate, so an already-canceled
// top-level context reaches this exact guard directly and deterministically;
// no mid-run cancellation trick is needed here (contrast
// TestGithubEnumerateWith_CanceledContextNowRecordsEverySlot in
// github_targets_test.go, where establishSession's own error handling
// intercepts an already-canceled context before the pool ever runs).
// ---------------------------------------------------------------------------

func TestTeamsEnumerateWith_CanceledContextNowRecordsEverySlot(t *testing.T) {
	t.Parallel()

	srv := newTargetsSearchServer(t)
	t.Cleanup(srv.Close)

	e := newTargetsTestEnumerator(t, srv)

	emails := []string{registeredEmail, "notfound@contoso.com", "nobody@contoso.com"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var mu sync.Mutex
	var cbResults []EnumResult

	results := e.EnumerateWith(ctx, emails, 4, 0, 0, func(r EnumResult) {
		mu.Lock()
		cbResults = append(cbResults, r)
		mu.Unlock()
	})

	require.Len(t, results, len(emails), "every slot must be filled even when ctx is already canceled")

	for i := range emails {
		assert.Equal(t, emails[i], results[i].Email,
			"results[%d].Email must be set (input order preserved), not left as a dropped zero-value", i)
		assert.Equal(t, ExistenceUnknown, results[i].Exists,
			"results[%d].Exists must be the valid ExistenceUnknown tri-state, not the zero-value empty string", i)
		require.Error(t, results[i].Error, "results[%d] must carry the ctx.Done() error, not be silently dropped", i)
		assert.True(t, errors.Is(results[i].Error, context.Canceled),
			"results[%d].Error must be context.Canceled from the <-ctx.Done() guard", i)
	}

	assert.Len(t, cbResults, len(emails), "onResult callback must fire exactly once per email, even on the canceled-context path")
}
