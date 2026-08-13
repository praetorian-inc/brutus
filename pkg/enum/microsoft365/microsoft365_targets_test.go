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
// to fail to compile until it is added to microsoft365.go.
package microsoft365

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// newTargetsMockServer builds an httptest.Server that reports every account
// as existing (IfExistsResult=0), except usernames whose local part contains
// "fail", which get a 500 response -- CheckAccount turns that into a genuine
// non-nil Result.Error ("unexpected status: 500") -- used to prove a name
// survives the error path.
func newTargetsMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req credTypeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if strings.Contains(req.Username, "fail") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(credTypeResponse{IfExistsResult: IfExistsResultExists})
	}))
}

// ---------------------------------------------------------------------------
// TestEnumerateTargetsWith_NamesRideOnResult
// Core test: 3 targets with distinct names against a stub that reports
// existence for all of them. Each returned Result must carry the name of the
// target that produced it, correlated by email. An implementation that
// stamps every Result with the first target's name fails this test.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_NamesRideOnResult(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "jsmith@x.com", First: "john", Last: "smith"},
		{Email: "dsmith@x.com", First: "david", Last: "smith"},
		{Email: "msmith@x.com", First: "michael", Last: "smith"},
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
		assert.Equal(t, tgt.First, r.First, "First for %q must match its own Target, not another target's", tgt.Email)
		assert.Equal(t, tgt.Last, r.Last, "Last for %q must match its own Target, not another target's", tgt.Email)
		assert.NoError(t, r.Error, "%q must succeed against the stub", tgt.Email)
		assert.True(t, r.Exists, "%q must be reported as existing by the stub", tgt.Email)
	}
}

// ---------------------------------------------------------------------------
// TestEnumerateTargetsWith_NamelessTargetStaysNameless
// A Target with no name (address supplied by the operator, not generated)
// must yield First=="" && Last=="". The library must never invent a name.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_NamelessTargetStaysNameless(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{{Email: "supplied@x.com"}}

	results := c.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].First, "First must stay empty for a nameless Target")
	assert.Empty(t, results[0].Last, "Last must stay empty for a nameless Target")
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_StillWorksAndYieldsEmptyNames
// Pins that the existing EnumerateWith([]string) entry point is unaffected by
// the refactor: it still returns correct results, and since bare addresses
// carry no name, First/Last must be empty.
// ---------------------------------------------------------------------------

func TestEnumerateWith_StillWorksAndYieldsEmptyNames(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{"a@x.com", "b@x.com", "c@x.com"}
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
		assert.True(t, r.Exists, "%q must be reported as existing by the stub", email)
		assert.Empty(t, r.First, "EnumerateWith must never invent a name")
		assert.Empty(t, r.Last, "EnumerateWith must never invent a name")
	}
}

// ---------------------------------------------------------------------------
// TestEnumerateTargetsWith_NamesSurviveErrorPath
// A name is a property of the address, not of the check outcome. Drive a
// Result whose Error is non-nil (stub returns 500 -> "unexpected status") and
// assert the name is still stamped.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_NamesSurviveErrorPath(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "failure@x.com", First: "erin", Last: "fail"},
	}

	results := c.EnumerateTargetsWith(context.Background(), targets, 1, 0, 0, nil)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "failure@x.com", r.Email)
	require.Error(t, r.Error, "the 500 response must surface as a non-nil Result.Error")
	assert.Equal(t, "erin", r.First, "name must survive even when the probe errors")
	assert.Equal(t, "fail", r.Last, "name must survive even when the probe errors")
}

// ---------------------------------------------------------------------------
// TestEnumerateTargetsWith_MixedNamedAndUnnamed
// A single batch containing both named and unnamed targets: each Result must
// get exactly its own target's name, or empty for the unnamed ones.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_MixedNamedAndUnnamed(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "named1@x.com", First: "anna", Last: "lee"},
		{Email: "unnamed1@x.com"},
		{Email: "named2@x.com", First: "bob", Last: "wu"},
		{Email: "unnamed2@x.com"},
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
// TestEnumerateTargetsWith_OrderingAndLength
// len(results) == len(targets) and every index is filled even when some
// probes fail. Completion order is not asserted (the worker pool is
// concurrent); correlation is by email.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_OrderingAndLength(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "ok1@x.com", First: "carl", Last: "one"},
		{Email: "fail1@x.com", First: "dana", Last: "two"},
		{Email: "ok2@x.com", First: "ella", Last: "three"},
		{Email: "fail2@x.com", First: "finn", Last: "four"},
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

	// Confirm the engineered failures actually failed and the others didn't,
	// proving this test exercises a genuinely mixed batch.
	assert.Error(t, byEmail["fail1@x.com"].Error)
	assert.Error(t, byEmail["fail2@x.com"].Error)
	assert.NoError(t, byEmail["ok1@x.com"].Error)
	assert.NoError(t, byEmail["ok2@x.com"].Error)
}

// ---------------------------------------------------------------------------
// TestEnumerateTargetsWith_NamesSurviveCancelledContext
// Chokepoint test: with the context already canceled before the call, every
// goroutine takes the <-ctx.Done() early-return branch and calls
// record(i, Result{Email: email, Error: ctx.Err()}) WITHOUT ever calling
// CheckAccount. If the name stamp lived only at the CheckAccount call site
// (record(i, *c.CheckAccount(...))) rather than inside record() itself, these
// Results would come back nameless. This is what makes record() the enforced
// chokepoint rather than an incidental detail.
// ---------------------------------------------------------------------------

func TestEnumerateTargetsWith_NamesSurviveCancelledContext(t *testing.T) {
	t.Parallel()
	srv := newTargetsMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	targets := []enum.Target{
		{Email: "one@x.com", First: "gwen", Last: "alpha"},
		{Email: "two@x.com", First: "hank", Last: "beta"},
		{Email: "three@x.com", First: "iris", Last: "gamma"},
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
