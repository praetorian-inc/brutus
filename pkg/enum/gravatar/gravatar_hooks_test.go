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

// Per-package hook-wiring tests for gravatar's enum.TargetWorker[Result]
// configuration (PLAN.md Part 3.3). These are wiring assertions, not a
// re-test of the pool: TargetWorker's generic behavior (ordering, panic
// isolation, concurrency bounds, callback serialization, etc.) is covered
// exactly once in pkg/enum/targetworker_test.go. What cannot be proven there
// is that THIS package wired its four hooks up correctly -- that Label is
// the exact string the pre-migration code used (panic diagnostics stay
// byte-identical), that NewError builds gravatar's real failure shape
// (Email, Hash, Error -- NOT dropping or adding a field), and that StampName
// copies only First/Last. worker() exists precisely so these are testable
// directly, without driving a live pool (PLAN.md Part 2, Part 3.3).
package gravatar

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
// gravatar's pre-migration panic diagnostics were prefixed "gravatar enum"
// (gravatar.go:152,156), yielding "gravatar enum: panic checking %s: %v" on
// stderr and "gravatar enum: panicked: %v" on the Result. The shared worker
// reproduces that prefix verbatim via Label, so this exact string must never
// drift -- changing it is a log-format change for anything that greps stderr
// or a Result's Error text, not a cosmetic rename.
// ---------------------------------------------------------------------------

func TestWorker_Label(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	assert.Equal(t, "gravatar enum", c.worker().Label)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape
//
// gravatar's failure results carry Email, Hash AND Error -- Hash is the one
// field a naive generic construction ("R{} + error field") would silently
// drop (PLAN.md Part 0.4, Part 2.3). Comparing the full struct -- not just
// Email/Error individually -- is deliberate and load-bearing here: an
// assertion that checked only Email and Error would pass even if Hash were
// missing, defeating the entire point of this test. Full-struct equality
// fails loudly on a dropped OR an unexpectedly added field.
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	sentinel := errors.New("sentinel")
	got := c.worker().NewError("a@b.com", sentinel)

	assert.Equal(t, Result{Email: "a@b.com", Hash: HashEmail("a@b.com"), Error: sentinel}, got)
}

// ---------------------------------------------------------------------------
// TestWorker_NewErrorShape_HashIsNormalizedNotVerbatimEmail
//
// HashEmail lowercases and trims internally, but Result.Email echoes the
// input verbatim. So a mixed-case/whitespace-padded address must produce a
// Result whose Email is untouched but whose Hash is computed from the
// normalized form -- an asymmetry worth pinning explicitly, since it is
// exactly the kind of thing a future "fix" might flatten by accident.
// ---------------------------------------------------------------------------

func TestWorker_NewErrorShape_HashIsNormalizedNotVerbatimEmail(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	const raw = "  John.Smith@Example.com  "
	sentinel := errors.New("sentinel")
	got := c.worker().NewError(raw, sentinel)

	assert.Equal(t, raw, got.Email, "Email must echo the input verbatim, uncased/untrimmed")
	assert.Equal(t, HashEmail(raw), got.Hash, "Hash must be computed from the normalized form")
	assert.NotEqual(t, got.Email, got.Hash)
}

// ---------------------------------------------------------------------------
// TestWorker_StampNameCopiesFirstLastOnly
// StampName's documented contract (targetworker.go) is a one-line copy of
// First/Last from the originating Target. This asserts both halves of that
// contract: First/Last land correctly, and every other field on an
// already-populated Result -- including Hash, gravatar's own extra field --
// is left untouched.
// ---------------------------------------------------------------------------

func TestWorker_StampNameCopiesFirstLastOnly(t *testing.T) {
	t.Parallel()

	c, err := NewChecker("", "", time.Second)
	require.NoError(t, err)

	res := Result{
		Email:    "a@b.com",
		Hash:     HashEmail("a@b.com"),
		Exists:   true,
		Error:    errors.New("unchanged-error"),
		Duration: 42 * time.Millisecond,
	}
	before := res

	c.worker().StampName(&res, enum.Target{Email: "a@b.com", First: "Jane", Last: "Doe"})

	assert.Equal(t, "Jane", res.First)
	assert.Equal(t, "Doe", res.Last)
	assert.Equal(t, before.Email, res.Email, "StampName must not touch Email")
	assert.Equal(t, before.Hash, res.Hash, "StampName must not touch Hash")
	assert.Equal(t, before.Exists, res.Exists, "StampName must not touch Exists")
	assert.Equal(t, before.Error, res.Error, "StampName must not touch Error")
	assert.Equal(t, before.Duration, res.Duration, "StampName must not touch Duration")
}
