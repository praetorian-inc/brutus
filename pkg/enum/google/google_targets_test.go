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
// concurrent). EnumerateTargetsWith does not exist yet; this file is expected
// to fail to compile until it is added to google.go.
package google

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// newTargetsMockServer builds an httptest.Server that reports every account as
// existing via the GXLU Gmail probe (AccountChooser always reports
// not-found, so every check falls through to GXLU). Emails whose local part
// contains "fail" cause the GXLU request to be hijacked and the underlying
// connection closed without a response, producing a genuine transport-level
// error out of CheckAccount -- used to prove a name survives the error path.
func newTargetsMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/AccountChooser", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://accounts.google.com/ServiceLogin")
		w.WriteHeader(http.StatusFound)
	})

	mux.HandleFunc("/mail/gxlu", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if strings.Contains(email, "fail") {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "GMAIL_AT", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateTargetsWith_NamesRideOnResult
// Core test: 3 targets with distinct names against a stub that reports
// existence for all of them. Each returned Result must carry the name of the
// target that produced it, correlated by email. An implementation that
// stamps every Result with the first target's name fails this test.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_NamesRideOnResult(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "jsmith@x.com", First: "john", Last: "smith"},
		{Email: "dsmith@x.com", First: "david", Last: "smith"},
		{Email: "msmith@x.com", First: "michael", Last: "smith"},
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
		assert.Equal(t, tgt.First, r.First, "First for %q must match its own Target, not another target's", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must match its own Target, not another target's", tgt.Email)
		assert.NoError(t, r.Error, "%q must succeed against the stub", tgt.Email)
		assert.True(t, r.Exists, "%q must be reported as existing by the stub", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateTargetsWith_NamelessTargetStaysNameless
// A Target with no name (address supplied by the operator, not generated)
// must yield First=="" && Last=="". The library must never invent a name.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{{Email: "supplied@x.com"}}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateWith_StillWorksAndYieldsEmptyNames
// Pins that the existing EnumerateWith([]string) entry point is unaffected by
// the refactor: it still returns correct results, and since bare addresses
// carry no name, First/Last must be empty.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateWith_StillWorksAndYieldsEmptyNames(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	emails := []string{"a@x.com", "b@x.com", "c@x.com"}
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
		assert.True(t, r.Exists, "%q must be reported as existing by the stub", email)
		assert.Empty(t, r.First, "EnumerateWith must never invent a name")
		assert.Empty(t, r.Last, "EnumerateWith must never invent a name")
	}
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateTargetsWith_NamesSurviveErrorPath
// A name is a property of the address, not of the check outcome. Drive a
// Result whose Error is non-nil (GXLU connection hijacked/closed) and assert
// the name is still stamped.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_NamesSurviveErrorPath(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "failure@x.com", First: "erin", Last: "fail"},
	}

	results := e.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "failure@x.com", r.Email)
	require.Error(t, r.Error, "the hijacked GXLU connection must surface as a transport error")
	assert.Equal(t, "erin", r.First, "name must survive even when the probe errors")
	assert.Equal(t, "fail", r.Last, "name must survive even when the probe errors")
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateTargetsWith_MixedNamedAndUnnamed
// A single batch containing both named and unnamed targets: each Result must
// get exactly its own target's name, or empty for the unnamed ones.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "named1@x.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@x.com"},
		{Email: "named2@x.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@x.com"},
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
// TestGoogleEnumerateTargetsWith_OrderingAndLength
// len(results) == len(targets) and every index is filled even when some
// probes fail. Completion order is not asserted (the worker pool is
// concurrent); correlation is by email.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_OrderingAndLength(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "ok1@x.com", First: "carl", Last: "one"},
		{Email: "fail1@x.com", First: "dana", Last: "two"},
		{Email: "ok2@x.com", First: "ella", Last: "three"},
		{Email: "fail2@x.com", First: "finn", Last: "four"},
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

	// Confirm the engineered failures actually failed and the others didn't,
	// proving this test exercises a genuinely mixed batch.
	assert.Error(t, byEmail["fail1@x.com"].Error)
	assert.Error(t, byEmail["fail2@x.com"].Error)
	assert.NoError(t, byEmail["ok1@x.com"].Error)
	assert.NoError(t, byEmail["ok2@x.com"].Error)
}

// ---------------------------------------------------------------------------
// TestGoogleEnumerateTargetsWith_NamesSurviveCancelledContext
// Chokepoint test: with the context already canceled before the call, every
// goroutine takes the <-ctx.Done() early-return branch and calls
// record(i, Result{Email: email, Error: ctx.Err()}) WITHOUT ever calling
// CheckAccount. If the name stamp lived only at the CheckAccount call site
// (record(i, e.CheckAccount(...))) rather than inside record() itself, these
// Results would come back nameless. This is what makes record() the enforced
// chokepoint rather than an incidental detail.
// ---------------------------------------------------------------------------

func TestGoogleEnumerateTargetsWith_NamesSurviveCancelledContext(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)

	targets := []enum.Target{
		{Email: "one@x.com", First: "gwen", Last: "alpha"},
		{Email: "two@x.com", First: "hank", Last: "beta"},
		{Email: "three@x.com", First: "iris", Last: "gamma"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled BEFORE the call

	results := e.EnumerateTargetsWith(ctx, targets, 1, 0, 0, nil)
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
