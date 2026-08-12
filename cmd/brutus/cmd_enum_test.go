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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// capResults — generic type parameter (10T-535, 3/8)
//
// cmd_enum_generate_test.go already exercises capResults over []string
// (its original, non-generic shape). This test exercises the generic
// signature (capResults[T any]) over a non-string element type, so the type
// parameter itself — not just the []string instantiation — is verified.
// ---------------------------------------------------------------------------

// TestCapResults_GenericOverNonStringType verifies that capResults works over
// a non-string type (enum.Target), proving it is generic rather than
// []string-specific.
func TestCapResults_GenericOverNonStringType(t *testing.T) {
	t.Parallel()

	input := []enum.Target{
		{Email: "alice@example.com", First: "alice", Last: "a"},
		{Email: "bob@example.com", First: "bob", Last: "b"},
		{Email: "carol@example.com", First: "carol", Last: "c"},
	}

	got := capResults(input, 2)
	assert.Equal(t, input[:2], got,
		"capResults[enum.Target] must cap to the first N elements, same as capResults[string]")
}

// ---------------------------------------------------------------------------
// enumTargetEmails
// ---------------------------------------------------------------------------

// TestEnumTargetEmails_PreservesOrder verifies that enumTargetEmails projects
// []enum.Target -> []string of addresses, preserving input order.
func TestEnumTargetEmails_PreservesOrder(t *testing.T) {
	t.Parallel()

	targets := []enum.Target{
		{Email: "carol@example.com", First: "carol", Last: "c"},
		{Email: "alice@example.com", First: "alice", Last: "a"},
		{Email: "bob@example.com"},
	}

	got := enumTargetEmails(targets)
	assert.Equal(t,
		[]string{"carol@example.com", "alice@example.com", "bob@example.com"},
		got,
		"enumTargetEmails must preserve the input order of targets")
}

// TestEnumTargetEmails_EmptyInput verifies that an empty/nil target slice
// yields an empty (not nil-panicking) result.
func TestEnumTargetEmails_EmptyInput(t *testing.T) {
	t.Parallel()

	got := enumTargetEmails(nil)
	assert.Empty(t, got, "enumTargetEmails on a nil slice must return an empty slice")
}

// ---------------------------------------------------------------------------
// enumNamesByEmail / enumNameFor
// ---------------------------------------------------------------------------

// TestEnumNamesByEmail_IndexesGeneratedTargets verifies that
// enumNamesByEmail builds an address -> name index from generated targets
// (non-empty First/Last), and omits targets that carry no name (as supplied
// --emails/--email-file addresses do).
func TestEnumNamesByEmail_IndexesGeneratedTargets(t *testing.T) {
	t.Parallel()

	targets := []enum.Target{
		{Email: "generated@example.com", First: "john", Last: "smith"},
		{Email: "supplied@example.com"}, // no name: CLI-supplied address
	}

	index := enumNamesByEmail(targets)

	require := assert.New(t)
	require.Len(index, 1, "enumNamesByEmail must only index targets that carry a name")
	got, ok := index["generated@example.com"]
	require.True(ok, "the generated target's address must be present in the index")
	require.Equal("john", got.First)
	require.Equal("smith", got.Last)

	_, ok = index["supplied@example.com"]
	require.False(ok, "a nameless (CLI-supplied) target must not appear in the index")
}

// TestEnumNameFor_HitReturnsIndexedName verifies that enumNameFor returns the
// indexed First/Last for an address present in the index.
func TestEnumNameFor_HitReturnsIndexedName(t *testing.T) {
	t.Parallel()

	index := enumNamesByEmail([]enum.Target{
		{Email: "jane@example.com", First: "jane", Last: "doe"},
	})

	first, last := enumNameFor(index, "jane@example.com")
	assert.Equal(t, "jane", first)
	assert.Equal(t, "doe", last)
}

// TestEnumNameFor_MissReturnsEmptyNeverDerived verifies that looking up an
// address absent from the index returns empty First/Last — the framework
// must never invent or derive a name for an address it didn't generate.
func TestEnumNameFor_MissReturnsEmptyNeverDerived(t *testing.T) {
	t.Parallel()

	index := enumNamesByEmail([]enum.Target{
		{Email: "jane@example.com", First: "jane", Last: "doe"},
	})

	// "unknown@example.com" was never generated and is absent from the index.
	first, last := enumNameFor(index, "unknown@example.com")
	assert.Empty(t, first, "a miss must yield an empty First, never a derived guess")
	assert.Empty(t, last, "a miss must yield an empty Last, never a derived guess")
}

// TestEnumNameFor_EmptyIndexReturnsEmpty verifies enumNameFor against a
// nil/empty index (e.g. no addresses were generated at all).
func TestEnumNameFor_EmptyIndexReturnsEmpty(t *testing.T) {
	t.Parallel()

	first, last := enumNameFor(map[string]enum.Target{}, "anyone@example.com")
	assert.Empty(t, first)
	assert.Empty(t, last)
}
