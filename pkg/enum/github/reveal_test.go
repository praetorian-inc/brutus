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

package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// RevealWith: onProgress callback sequencing
// ---------------------------------------------------------------------------

// TestRevealWith_ProgressCallback verifies that RevealWith invokes onProgress
// exactly once per email, with strictly increasing done values 1, 2, …, N and
// total always equal to len(emails). The final invocation must have done ==
// len(emails).
func TestRevealWith_ProgressCallback(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-progress-cb"

	emails := []string{
		"alice@example.com",
		"bob@example.com",
		"carol@example.com",
	}

	// Build emailToLogin with all three emails so the commit listing succeeds.
	loginAlice := "alice-gh"
	loginBob := "bob-gh"
	loginCarol := "carol-gh"
	emailToLogin := map[string]*string{
		"alice@example.com": &loginAlice,
		"bob@example.com":   &loginBob,
		"carol@example.com": &loginCarol,
	}

	apiSrv := newAPIServer(t, token, emailToLogin, 0)
	e := newTestEnumerator(t, nil, apiSrv, token)

	// Collect (done, total) pairs from the callback in order.
	type pair struct{ done, total int }
	var calls []pair

	mapping, err := e.RevealWith(context.Background(), emails, func(done, total int) {
		calls = append(calls, pair{done, total})
	})

	require.NoError(t, err)

	// mapping must be non-nil even though we care about the callback here.
	require.NotNil(t, mapping)

	// Callback must be invoked exactly once per email.
	require.Len(t, calls, len(emails),
		"onProgress must be called exactly once per email")

	// done must be strictly increasing 1 … N and total must always be N.
	N := len(emails)
	for i, c := range calls {
		assert.Equal(t, i+1, c.done,
			"call[%d]: done must be %d (1-based), got %d", i, i+1, c.done)
		assert.Equal(t, N, c.total,
			"call[%d]: total must be %d (len(emails)), got %d", i, N, c.total)
	}

	// Final invocation must have done == len(emails).
	last := calls[len(calls)-1]
	assert.Equal(t, N, last.done,
		"last callback invocation must have done == len(emails)")
}

// TestRevealWith_NilCallback verifies that passing a nil onProgress callback to
// RevealWith works correctly (Reveal's thin wrapper relies on this).
func TestRevealWith_NilCallback(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-nil-cb"

	loginAlice := "alice-gh"
	emailToLogin := map[string]*string{
		"alice@example.com": &loginAlice,
	}

	apiSrv := newAPIServer(t, token, emailToLogin, 0)
	e := newTestEnumerator(t, nil, apiSrv, token)

	// Must not panic with nil callback — this is the Reveal path.
	mapping, err := e.RevealWith(context.Background(), []string{"alice@example.com"}, nil)

	require.NoError(t, err)
	assert.Equal(t, "alice-gh", mapping["alice@example.com"])
}
