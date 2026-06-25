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
)

// ---------------------------------------------------------------------------
// capResults
// ---------------------------------------------------------------------------

// TestCapResults_LimitToN verifies that capResults returns exactly N items
// when limit <= len(results).
func TestCapResults_LimitToN(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c", "d", "e"}
	got := capResults(input, 3)
	assert.Equal(t, []string{"a", "b", "c"}, got,
		"capResults must return the first N items when N <= len(results)")
}

// TestCapResults_LimitGreaterThanSlice verifies that capResults returns the
// entire slice when limit > len(results).
func TestCapResults_LimitGreaterThanSlice(t *testing.T) {
	t.Parallel()

	input := []string{"x", "y"}
	got := capResults(input, 100)
	assert.Equal(t, input, got,
		"capResults must return all items when limit exceeds slice length")
}

// TestCapResults_ZeroLimitMeansAll verifies that limit=0 means no cap
// (all items returned).
func TestCapResults_ZeroLimitMeansAll(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c"}
	got := capResults(input, 0)
	assert.Equal(t, input, got,
		"capResults with limit=0 must return all items (no cap)")
}

// TestCapResults_NegativeLimitMeansAll verifies that a negative limit also
// means no cap.
func TestCapResults_NegativeLimitMeansAll(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c"}
	got := capResults(input, -5)
	assert.Equal(t, input, got,
		"capResults with limit<0 must return all items (no cap)")
}

// TestCapResults_LimitEqualsLen verifies that limit == len(results) returns
// all items (boundary condition).
func TestCapResults_LimitEqualsLen(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c"}
	got := capResults(input, len(input))
	assert.Equal(t, input, got,
		"capResults with limit==len(results) must return all items")
}

// TestCapResults_EmptyInput verifies that capResults handles an empty slice
// gracefully for any limit value.
func TestCapResults_EmptyInput(t *testing.T) {
	t.Parallel()

	got := capResults([]string{}, 5)
	assert.Empty(t, got, "capResults on empty slice must return empty slice")
}
