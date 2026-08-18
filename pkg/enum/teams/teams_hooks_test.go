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

// Per-package hook-wiring tests for teams' enum.TargetWorker[EnumResult]
// configuration (PLAN.md Part 3.3). These are wiring assertions, not a
// re-test of the pool: TargetWorker's generic behavior (ordering, panic
// isolation, concurrency bounds, callback serialization, etc.) is covered
// exactly once in pkg/enum/targetworker_test.go. What cannot be proven there
// is that THIS package wired its four hooks up correctly -- that Label is
// the exact string the pre-migration code used (panic diagnostics stay
// byte-identical), that NewError builds teams' real failure shape (Email,
// Exists: ExistenceUnknown, Error -- Exists is the field a naive generic
// construction would leave as the invalid empty string), and that StampName
// copies only First/Last. worker() exists precisely so these are testable
// directly, without driving a live pool (PLAN.md Part 2.4, Part 3.3).
//
// worker() is not yet defined on *Enumerator; this file is expected to fail
// to compile until it, newError and the pkg/enum import are added to enum.go
// (PLAN.md Part 2.4).
package teams

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
// teams' pre-migration panic diagnostics were prefixed "teams enum"
// (enum.go:227,231), yielding "teams enum: panic checking %s: %v" on stderr
// and "teams enum: panicked: %v" on the EnumResult. The shared worker
// reproduces that prefix verbatim via Label, so this exact string must never
// drift -- changing it is a log-format change for anything that greps stderr
// or an EnumResult's Error text, not a cosmetic rename.
// ---------------------------------------------------------------------------

func TestWorker_Label(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("tok", "", "", time.Second, false)
	require.NoError(t, err)

	assert.Equal(t, "teams enum", e.worker().Label)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape
//
// teams' failure results carry Email, Exists AND Error -- Exists is the one
// field a naive generic construction ("R{} + error field") would silently
// leave at its zero value: the empty string, which is NOT a valid member of
// the Existence tri-state-plus-unknown set that DerivePosture reads (PLAN.md
// Part 0.4, Part 2.4). Comparing the full struct -- not just Email/Error
// individually -- is deliberate and load-bearing here: an assertion that
// checked only Email and Error would pass even if Exists were left empty,
// defeating the entire point of this test.
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("tok", "", "", time.Second, false)
	require.NoError(t, err)

	sentinel := errors.New("sentinel")
	got := e.worker().NewError("a@b.com", sentinel)

	assert.Equal(t, EnumResult{Email: "a@b.com", Exists: ExistenceUnknown, Error: sentinel}, got)
}

// ---------------------------------------------------------------------------
// TestWorker_StampNameCopiesFirstLastOnly
// StampName's documented contract (targetworker.go) is a one-line copy of
// First/Last from the originating Target. This asserts both halves of that
// contract: First/Last land correctly, and every other field on an
// already-populated EnumResult -- including Exists, teams' own tri-state
// field -- is left untouched.
// ---------------------------------------------------------------------------

func TestWorker_StampNameCopiesFirstLastOnly(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("tok", "", "", time.Second, false)
	require.NoError(t, err)

	res := EnumResult{
		Email:       "a@b.com",
		Exists:      ExistenceYes,
		DisplayName: "Existing Name",
		MRI:         "8:orgid:abc",
		Error:       errors.New("unchanged-error"),
	}
	before := res

	e.worker().StampName(&res, enum.Target{Email: "a@b.com", First: "Jane", Last: "Doe"})

	assert.Equal(t, "Jane", res.First)
	assert.Equal(t, "Doe", res.Last)
	assert.Equal(t, before.Email, res.Email, "StampName must not touch Email")
	assert.Equal(t, before.Exists, res.Exists, "StampName must not touch Exists")
	assert.Equal(t, before.DisplayName, res.DisplayName, "StampName must not touch DisplayName")
	assert.Equal(t, before.MRI, res.MRI, "StampName must not touch MRI")
	assert.Equal(t, before.Error, res.Error, "StampName must not touch Error")
}
