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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	m365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

// ---------------------------------------------------------------------------
// Test: outputEnumErrorBreakdown — empty input prints nothing
// ---------------------------------------------------------------------------

func TestOutputEnumErrorBreakdown_EmptyPrintsNothing(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		var buf bytes.Buffer
		outputEnumErrorBreakdown(&buf, nil, false /* useColor */)
		assert.Empty(t, buf.String(), "nil errMsgs must produce no output")
	})

	t.Run("empty slice", func(t *testing.T) {
		var buf bytes.Buffer
		outputEnumErrorBreakdown(&buf, []string{}, false /* useColor */)
		assert.Empty(t, buf.String(), "empty errMsgs must produce no output")
		assert.NotContains(t, buf.String(), "Top errors:")
	})
}

// ---------------------------------------------------------------------------
// Test: outputEnumErrorBreakdown — groups identical messages with correct counts
// ---------------------------------------------------------------------------

func TestOutputEnumErrorBreakdown_GroupingAndCounts(t *testing.T) {
	errMsgs := []string{
		"proxy: 407 Proxy Authentication Required",
		"proxy: 407 Proxy Authentication Required",
		"proxy: 407 Proxy Authentication Required",
		"context deadline exceeded",
		"context deadline exceeded",
		"tls: handshake failure",
	}

	var buf bytes.Buffer
	outputEnumErrorBreakdown(&buf, errMsgs, false /* useColor */)
	out := buf.String()

	assert.Contains(t, out, "Top errors:")
	assert.Contains(t, out, "3×  proxy: 407 Proxy Authentication Required",
		"the 407 message must be grouped and counted 3 times")
	assert.Contains(t, out, "2×  context deadline exceeded",
		"the deadline message must be grouped and counted 2 times")
	assert.Contains(t, out, "1×  tls: handshake failure",
		"the tls message must appear once")
}

// ---------------------------------------------------------------------------
// Test: outputEnumErrorBreakdown — sort order (count desc, message asc tie-break)
// ---------------------------------------------------------------------------

func TestOutputEnumErrorBreakdown_SortOrder(t *testing.T) {
	t.Run("higher count sorts before lower count", func(t *testing.T) {
		errMsgs := []string{
			"low count error",
			"high count error", "high count error", "high count error",
		}

		var buf bytes.Buffer
		outputEnumErrorBreakdown(&buf, errMsgs, false /* useColor */)
		out := buf.String()

		highIdx := strings.Index(out, "high count error")
		lowIdx := strings.Index(out, "low count error")
		assert.Greater(t, highIdx, -1, "high count message must appear")
		assert.Greater(t, lowIdx, -1, "low count message must appear")
		assert.Less(t, highIdx, lowIdx,
			"higher-count group must appear before lower-count group")
	})

	t.Run("equal counts tie-break by message ascending", func(t *testing.T) {
		errMsgs := []string{"zebra error", "alpha error"}

		var buf bytes.Buffer
		outputEnumErrorBreakdown(&buf, errMsgs, false /* useColor */)
		out := buf.String()

		alphaIdx := strings.Index(out, "alpha error")
		zebraIdx := strings.Index(out, "zebra error")
		assert.Greater(t, alphaIdx, -1, "alpha error must appear")
		assert.Greater(t, zebraIdx, -1, "zebra error must appear")
		assert.Less(t, alphaIdx, zebraIdx,
			"equal-count groups must tie-break by message ascending")
	})
}

// ---------------------------------------------------------------------------
// Test: outputEnumErrorBreakdown — top-N cap and "… and K more" remainder
// ---------------------------------------------------------------------------

func TestOutputEnumErrorBreakdown_TopNCapAndRemainder(t *testing.T) {
	// 8 distinct messages, each appearing once (equal counts -> alphabetic
	// tie-break), so exactly the first 5 alphabetically are shown and the
	// remaining 3 distinct messages collapse into "… and 3 more".
	errMsgs := []string{
		"error-a", "error-b", "error-c", "error-d",
		"error-e", "error-f", "error-g", "error-h",
	}

	var buf bytes.Buffer
	outputEnumErrorBreakdown(&buf, errMsgs, false /* useColor */)
	out := buf.String()

	rowCount := strings.Count(out, "1×  error-")
	assert.Equal(t, enumErrorBreakdownTopN, rowCount,
		"exactly enumErrorBreakdownTopN rows must be printed")

	wantRemaining := len(errMsgs) - enumErrorBreakdownTopN // 8 distinct - 5 shown = 3
	assert.Contains(t, out, fmt.Sprintf("… and %d more", wantRemaining),
		"remainder line must report the number of distinct messages not shown")

	// The alphabetically-last messages (f, g, h) must not have their own row.
	assert.NotContains(t, out, "1×  error-f")
	assert.NotContains(t, out, "1×  error-g")
	assert.NotContains(t, out, "1×  error-h")
}

// ---------------------------------------------------------------------------
// Test: outputEnumErrorBreakdown — single error, no remainder line
// ---------------------------------------------------------------------------

func TestOutputEnumErrorBreakdown_SingleError(t *testing.T) {
	var buf bytes.Buffer
	outputEnumErrorBreakdown(&buf, []string{"only error"}, false /* useColor */)
	out := buf.String()

	assert.Contains(t, out, "Top errors:")
	assert.Contains(t, out, "1×  only error")
	assert.NotContains(t, out, "more",
		"a single distinct error must not print a remainder line")
}

// ---------------------------------------------------------------------------
// Test: outputMicrosoft365EnumSummary — full summary renders the error
// breakdown block for erroring results.
// ---------------------------------------------------------------------------

func TestOutputMicrosoft365EnumSummary_IncludesErrorBreakdown(t *testing.T) {
	results := []m365.Result{
		{Email: "a@contoso.com", Exists: false, Error: errors.New("proxy: 407 Proxy Authentication Required")},
		{Email: "b@contoso.com", Exists: false, Error: errors.New("proxy: 407 Proxy Authentication Required")},
		{Email: "c@contoso.com", Exists: false, Error: errors.New("context deadline exceeded")},
	}

	var buf bytes.Buffer
	outputMicrosoft365EnumSummary(&buf, results, false /* useColor */)
	out := buf.String()

	assert.Contains(t, out, "Errors:")
	assert.Contains(t, out, "Top errors:")
	assert.Contains(t, out, "2×  proxy: 407 Proxy Authentication Required")
	assert.Contains(t, out, "1×  context deadline exceeded")
}
