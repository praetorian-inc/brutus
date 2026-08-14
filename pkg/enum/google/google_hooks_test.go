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

// Per-package hook-wiring tests for google's enum.TargetWorker[Result]
// configuration (PLAN.md Part 3.3). These are wiring assertions, not a
// re-test of the pool: TargetWorker's generic behavior (ordering, panic
// isolation, concurrency bounds, callback serialization, etc.) is covered
// exactly once in pkg/enum/targetworker_test.go. What cannot be proven there
// is that THIS package wired its four hooks up correctly -- that Label is
// the exact string the pre-migration code used (panic diagnostics stay
// byte-identical), that NewError builds google's real failure shape without
// dropping or adding a field, and that StampName copies only First/Last.
// worker() exists precisely so these are testable directly, without driving
// a live pool (PLAN.md Part 2, Part 3.3).
package google

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// TestWorker_Label
// google's pre-migration panic diagnostics were prefixed "google enum",
// yielding "google enum: panic checking %s: %v" on stderr and "google enum:
// panicked: %v" on the Result (PLAN.md Part 1.4). The shared worker reproduces
// that prefix verbatim via Label, so this exact string must never drift --
// changing it is a log-format change for anything that greps stderr or a
// Result's Error text, not a cosmetic rename.
// ---------------------------------------------------------------------------

func TestWorker_Label(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", time.Second)
	require.NoError(t, err)

	assert.Equal(t, "google enum", e.worker().Label)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape
// google's failure results carry no fields beyond Email and Error (PLAN.md
// Part 0.4). Comparing the full struct -- not just Email/Error individually --
// is deliberate: it is the same assertion shape that would have caught
// gravatar's Hash regression had it been applied there, so it must prove a
// negative (nothing else got set) as well as a positive (Email/Error got
// set).
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", time.Second)
	require.NoError(t, err)

	sentinel := errors.New("sentinel")
	got := e.worker().NewError("a@b.com", sentinel)

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

	e, err := NewEnumerator("", time.Second)
	require.NoError(t, err)

	res := Result{
		Email:  "a@b.com",
		Exists: true,
		Method: MethodGmail,
		IdP:    "unchanged-idp",
		Error:  errors.New("unchanged-error"),
	}
	before := res

	e.worker().StampName(&res, enum.Target{Email: "a@b.com", First: "Jane", Last: "Doe"})

	assert.Equal(t, "Jane", res.First)
	assert.Equal(t, "Doe", res.Last)
	assert.Equal(t, before.Email, res.Email, "StampName must not touch Email")
	assert.Equal(t, before.Exists, res.Exists, "StampName must not touch Exists")
	assert.Equal(t, before.Method, res.Method, "StampName must not touch Method")
	assert.Equal(t, before.IdP, res.IdP, "StampName must not touch IdP")
	assert.Equal(t, before.Error, res.Error, "StampName must not touch Error")
}
