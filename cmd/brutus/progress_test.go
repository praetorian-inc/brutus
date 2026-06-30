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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// progressLine tests
// ---------------------------------------------------------------------------

// TestProgressLine_MidScan verifies the format of a mid-scan progress line with
// a known total. The output must contain the bar brackets, percentage, count,
// ETA label, and the custom metrics tail.
func TestProgressLine_MidScan(t *testing.T) {
	t.Parallel()

	line := progressLine(4200, 10000, 110*time.Second, "8 found")

	// Must start with the info symbol.
	assert.True(t, strings.HasPrefix(line, SymbolInfo),
		"progressLine must start with SymbolInfo (%q), got: %q", SymbolInfo, line)

	// Bar brackets must be present.
	assert.Contains(t, line, "[", "must contain opening bar bracket")
	assert.Contains(t, line, "]", "must contain closing bar bracket")

	// Percentage.
	assert.Contains(t, line, "42%", "must contain 42% for 4200/10000")

	// Count.
	assert.Contains(t, line, "4200/10000", "must contain processed/total count")

	// ETA label.
	assert.Contains(t, line, "ETA", "must contain ETA label when total > 0")

	// Metrics tail.
	assert.Contains(t, line, "8 found", "must contain custom metrics string")
}

// TestProgressLine_UnknownTotal verifies that when total==0 the bar, percentage,
// and ETA are omitted but the raw count is still shown.
func TestProgressLine_UnknownTotal(t *testing.T) {
	t.Parallel()

	line := progressLine(37, 0, 5*time.Second, "")

	// Must start with the info symbol.
	assert.True(t, strings.HasPrefix(line, SymbolInfo),
		"progressLine must start with SymbolInfo when total==0")

	// Raw count must be present.
	assert.Contains(t, line, "37", "must contain raw processed count")

	// Percentage, ETA, and bar must be absent.
	assert.NotContains(t, line, "%", "must NOT contain percentage when total==0")
	assert.NotContains(t, line, "ETA", "must NOT contain ETA when total==0")
	assert.NotContains(t, line, "[====", "must NOT contain bar when total==0")
}

// TestProgressLine_ZeroProcessed verifies the placeholder values shown before
// any progress has been made.
func TestProgressLine_ZeroProcessed(t *testing.T) {
	t.Parallel()

	line := progressLine(0, 100, 10*time.Second, "")

	// Rate must show "--/s" when processed==0.
	assert.Contains(t, line, "--/s", "rate must be '--/s' when processed==0")

	// ETA must show "--" when processed==0.
	assert.Contains(t, line, "ETA --", "ETA must be '--' when processed==0")
}

// ---------------------------------------------------------------------------
// formatDuration table tests
// ---------------------------------------------------------------------------

// TestFormatDuration covers the coarse human-friendly rendering of durations.
func TestFormatDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{
			name:     "sub-second renders as 0s",
			input:    500 * time.Millisecond,
			expected: "0s",
		},
		{
			name:     "exactly 45 seconds",
			input:    45 * time.Second,
			expected: "45s",
		},
		{
			name:     "152 seconds renders as 2m32s",
			input:    152 * time.Second,
			expected: "2m32s",
		},
		{
			name:     "3780 seconds renders as 1h03m",
			input:    3780 * time.Second,
			expected: "1h03m",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, formatDuration(tc.input))
		})
	}
}

// ---------------------------------------------------------------------------
// progressRate tests
// ---------------------------------------------------------------------------

// TestProgressRate covers the throughput formatting for edge cases and both
// decimal regimes.
func TestProgressRate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		processed int
		elapsed   time.Duration
		expected  string
	}{
		{
			name:      "zero processed returns placeholder",
			processed: 0,
			elapsed:   10 * time.Second,
			expected:  "--/s",
		},
		{
			name:      "negative processed returns placeholder",
			processed: -1,
			elapsed:   10 * time.Second,
			expected:  "--/s",
		},
		{
			name:      "zero elapsed returns placeholder",
			processed: 10,
			elapsed:   0,
			expected:  "--/s",
		},
		{
			name:      "negative elapsed returns placeholder",
			processed: 10,
			elapsed:   -1 * time.Second,
			expected:  "--/s",
		},
		{
			name:      "slow rate (< 10/s) keeps one decimal: 5 items / 2s = 2.5/s",
			processed: 5,
			elapsed:   2 * time.Second,
			expected:  "2.5/s",
		},
		{
			name:      "fast rate (>= 10/s) has no decimal: 100 items / 2s = 50/s",
			processed: 100,
			elapsed:   2 * time.Second,
			expected:  "50/s",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, progressRate(tc.processed, tc.elapsed))
		})
	}
}

// ---------------------------------------------------------------------------
// Disabled reporter produces no output
// ---------------------------------------------------------------------------

// TestProgressReporter_DisabledNoOutput verifies that a reporter constructed
// with enabled=false is a complete no-op: Start, Update, Clear, and Stop all
// produce no bytes in the output writer.
func TestProgressReporter_DisabledNoOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := newProgressReporter(&buf, 100, false, false)

	p.Start()
	p.Update(5, "x")
	p.Clear()
	p.Stop()

	assert.Equal(t, 0, buf.Len(), "disabled reporter must produce no output bytes")
}

// ---------------------------------------------------------------------------
// Non-TTY flush: deterministic elapsed via injected clock
// ---------------------------------------------------------------------------

// TestProgressReporter_NonTTYFlush verifies that calling flush(true) on a
// non-TTY reporter writes a newline-terminated line containing the expected
// percentage, count, and metrics. The clock is injected to make elapsed
// deterministic.
func TestProgressReporter_NonTTYFlush(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := newProgressReporter(&buf, 10000, true, false) // enabled, no color

	// Inject a fixed clock so elapsed is exactly 110 s.
	fixed := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	p.start = fixed.Add(-110 * time.Second)
	p.now = func() time.Time { return fixed }

	p.Update(4200, "8 found")
	p.flush(true)

	out := buf.String()

	// Must be newline-terminated.
	require.True(t, strings.HasSuffix(out, "\n"),
		"non-TTY flush must produce a newline-terminated line, got: %q", out)

	// Must contain expected content.
	assert.Contains(t, out, "42%", "must contain 42% for 4200/10000")
	assert.Contains(t, out, "4200/10000", "must contain processed/total count")
	assert.Contains(t, out, "8 found", "must contain metrics tail")
}
