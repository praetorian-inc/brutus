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

// Per-package hook-wiring tests for microsoft365's enum.TargetWorker[Result]
// configuration (PLAN.md Part 3.3). These are wiring assertions, not a
// re-test of the pool: TargetWorker's generic behavior (ordering, panic
// isolation, concurrency bounds, callback serialization, etc.) is covered
// exactly once in pkg/enum/targetworker_test.go. What cannot be proven there
// is that THIS package wired its four hooks up correctly -- that Label is
// the exact string the pre-migration code used (panic diagnostics stay
// byte-identical), that NewError builds microsoft365's real failure shape
// without dropping or adding a field, that StampName copies only
// First/Last, and that the nil-result guard in worker()'s Check adapter
// routes through the package's own newError rather than a bare struct
// literal. worker() exists precisely so these are testable directly,
// without driving a live pool (PLAN.md Part 2, Part 3.3).
package microsoft365

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// TestWorker_Label
// microsoft365's pre-migration panic diagnostics were prefixed
// "microsoft365 enum", yielding "microsoft365 enum: panic checking %s: %v"
// on stderr and "microsoft365 enum: panicked: %v" on the Result (PLAN.md
// Part 1.4). The shared worker reproduces that prefix verbatim via Label, so
// this exact string must never drift -- changing it is a log-format change
// for anything that greps stderr or a Result's Error text, not a cosmetic
// rename.
// ---------------------------------------------------------------------------

func TestWorker_Label(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	assert.Equal(t, "microsoft365 enum", c.worker().Label)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape
// microsoft365's failure results carry no fields beyond Email and Error
// (PLAN.md Part 0.4). Comparing the full struct -- not just Email/Error
// individually -- is deliberate: it is the same assertion shape that would
// have caught gravatar's Hash regression had it been applied there, so it
// must prove a negative (nothing else got set) as well as a positive
// (Email/Error got set).
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	sentinel := errors.New("sentinel")
	got := c.worker().NewError("a@b.com", sentinel)

	assert.Equal(t, Result{Email: "a@b.com", Error: sentinel}, got)
}

// ---------------------------------------------------------------------------
// TestWorker_StampNameCopiesFirstLastOnly
// StampName's documented contract (targetworker.go) is a one-line copy of
// First/Last from the originating Target. This asserts both halves of that
// contract: First/Last land correctly, and every other field on an
// already-populated Result is left untouched.
// ---------------------------------------------------------------------------

func TestWorker_StampNameCopiesFirstLastOnly(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	res := Result{
		Email:          "a@b.com",
		Exists:         true,
		IfExistsResult: 1,
		Federated:      true,
		FederationURL:  "https://unchanged.example.com",
		Error:          errors.New("unchanged-error"),
		Duration:       5 * time.Second,
	}
	before := res

	c.worker().StampName(&res, enum.Target{Email: "a@b.com", First: "Jane", Last: "Doe"})

	assert.Equal(t, "Jane", res.First)
	assert.Equal(t, "Doe", res.Last)
	assert.Equal(t, before.Email, res.Email, "StampName must not touch Email")
	assert.Equal(t, before.Exists, res.Exists, "StampName must not touch Exists")
	assert.Equal(t, before.IfExistsResult, res.IfExistsResult, "StampName must not touch IfExistsResult")
	assert.Equal(t, before.Federated, res.Federated, "StampName must not touch Federated")
	assert.Equal(t, before.FederationURL, res.FederationURL, "StampName must not touch FederationURL")
	assert.Equal(t, before.Error, res.Error, "StampName must not touch Error")
	assert.Equal(t, before.Duration, res.Duration, "StampName must not touch Duration")
}

// ---------------------------------------------------------------------------
// TestWorker_NilResultGuardRoutesThroughNewError
//
// PLAN.md Part 3.3 requires that microsoft365's nil-result substitute route
// through the package's own newError rather than a bare struct literal, so
// the failure shape stays identical to every other failure this package
// produces (in particular, so a future field added to newError is not
// silently skipped on this one path).
//
// This test does NOT exercise the `if r == nil` branch inside worker()'s
// Check closure. That branch has no reachable seam: CheckAccount cannot be
// made to return nil through microsoft365's public API today (confirmed
// against source, PLAN.md Part 3.3), and worker() does not expose an
// injectable probe function -- inventing one (e.g. a checkAccountFn field)
// solely to reach an otherwise-unreachable defensive branch would be
// complexity added for a test's benefit, not the product's
// (preferring-simple-solutions). So what this test asserts instead is that
// the exact substitute the guard is documented to construct --
// newError(email, fmt.Errorf("microsoft365 enum: nil result for %s",
// email)) -- produces the real, undamaged failure shape when run through
// the package's real NewError. It is the strongest assertion reachable
// without contorting the production code for testability; it does not prove
// the guard itself is reached.
// ---------------------------------------------------------------------------

func TestWorker_NilResultGuardRoutesThroughNewError(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	email := "a@b.com"
	wantErr := fmt.Errorf("microsoft365 enum: nil result for %s", email)

	got := c.worker().NewError(email, wantErr)

	assert.Equal(t, Result{Email: email, Error: wantErr}, got)
	require.Error(t, got.Error)
	assert.Equal(t, "microsoft365 enum: nil result for a@b.com", got.Error.Error())
}
