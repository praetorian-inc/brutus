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

// Per-package hook-wiring tests for github's enum.TargetWorker[Result]
// configuration (PLAN.md Part 3.3). These are wiring assertions, not a
// re-test of the pool: TargetWorker's generic behavior (ordering, panic
// isolation, concurrency bounds, callback serialization, etc.) is covered
// exactly once in pkg/enum/targetworker_test.go. What cannot be proven there
// is that THIS package wired its four hooks up correctly -- that Label is
// the exact string the pre-migration code used (panic diagnostics stay
// byte-identical), that NewError builds github's real failure shape (Email,
// Error -- no extra fields), and that StampName copies only First/Last.
// worker() exists precisely so these are testable directly, without driving
// a live pool or an established session (PLAN.md Part 2.5, Part 3.3).
//
// worker() is not yet defined on *Enumerator; this file is expected to fail
// to compile until it, newError and the pkg/enum import are added to
// existence.go (PLAN.md Part 2.5).
package github

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
// github's pre-migration panic diagnostics were prefixed "github enum"
// (existence.go:102,105), yielding "github enum: panic checking %s: %v" on
// stderr and "github enum: panicked: %v" on the Result. The shared worker
// reproduces that prefix verbatim via Label, so this exact string must never
// drift -- changing it is a log-format change for anything that greps stderr
// or a Result's Error text, not a cosmetic rename.
// ---------------------------------------------------------------------------

func TestWorker_Label(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", time.Second, "", false)
	require.NoError(t, err)

	// worker takes the already-established session as a parameter (PLAN.md
	// Part 2.5); Label/NewError/StampName never read it, so a dummy session is
	// sufficient for this wiring assertion -- no live join/validity endpoint
	// is needed.
	assert.Equal(t, "github enum", e.worker(&session{}).Label)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape
//
// github's failure results carry ONLY Email and Error -- no extra fields
// (unlike gravatar's Hash or teams' Exists: ExistenceUnknown). Full-struct
// equality is deliberate here too: it fails loudly if a future change adds an
// unexpected field to github's failure shape, not just if Email/Error are
// individually wrong.
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", time.Second, "", false)
	require.NoError(t, err)

	sentinel := errors.New("sentinel")
	got := e.worker(&session{}).NewError("a@b.com", sentinel)

	assert.Equal(t, Result{Email: "a@b.com", Error: sentinel}, got)
}

// ---------------------------------------------------------------------------
// TestWorker_StampNameCopiesFirstLastOnly
// StampName's documented contract (targetworker.go) is a one-line copy of
// First/Last from the originating Target. This asserts both halves of that
// contract: First/Last land correctly, and every other field on an
// already-populated Result -- including Username, github's reveal-only
// field -- is left untouched.
// ---------------------------------------------------------------------------

func TestWorker_StampNameCopiesFirstLastOnly(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", time.Second, "", false)
	require.NoError(t, err)

	res := Result{
		Email:    "a@b.com",
		Exists:   true,
		Username: "existing-login",
		Error:    errors.New("unchanged-error"),
	}
	before := res

	e.worker(&session{}).StampName(&res, enum.Target{Email: "a@b.com", First: "Jane", Last: "Doe"})

	assert.Equal(t, "Jane", res.First)
	assert.Equal(t, "Doe", res.Last)
	assert.Equal(t, before.Email, res.Email, "StampName must not touch Email")
	assert.Equal(t, before.Exists, res.Exists, "StampName must not touch Exists")
	assert.Equal(t, before.Username, res.Username, "StampName must not touch Username")
	assert.Equal(t, before.Error, res.Error, "StampName must not touch Error")
}
