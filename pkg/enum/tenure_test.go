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

package enum

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseFlexibleDate
// ---------------------------------------------------------------------------

func TestParseFlexibleDate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		wantYear  int
		wantMonth time.Month
		wantDay   int
		wantPrec  string
		wantOK    bool
	}{
		{
			name:      "day precision",
			input:     "2020-01-15",
			wantYear:  2020,
			wantMonth: time.January,
			wantDay:   15,
			wantPrec:  "day",
			wantOK:    true,
		},
		{
			name:      "month precision",
			input:     "2020-01",
			wantYear:  2020,
			wantMonth: time.January,
			wantDay:   1, // month layout parses to first of the month
			wantPrec:  "month",
			wantOK:    true,
		},
		{
			name:      "year precision",
			input:     "2020",
			wantYear:  2020,
			wantMonth: time.January,
			wantDay:   1, // year layout parses to Jan 1
			wantPrec:  "year",
			wantOK:    true,
		},
		{name: "empty string", input: "", wantOK: false},
		{name: "garbage string", input: "garbage", wantOK: false},
		{name: "invalid month 13", input: "2020-13", wantOK: false},
		{name: "invalid day 32", input: "2020-01-32", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, prec, ok := ParseFlexibleDate(tc.input)
			require.Equal(t, tc.wantOK, ok, "ok mismatch")
			if !tc.wantOK {
				return
			}
			// Parsed time must be UTC.
			assert.Equal(t, time.UTC, got.Location(), "parsed time must be UTC")
			assert.Equal(t, tc.wantYear, got.Year(), "year mismatch")
			assert.Equal(t, tc.wantMonth, got.Month(), "month mismatch")
			assert.Equal(t, tc.wantDay, got.Day(), "day mismatch")
			assert.Equal(t, tc.wantPrec, prec, "precision mismatch")
		})
	}
}

// ---------------------------------------------------------------------------
// MonthsBetween
// ---------------------------------------------------------------------------

func TestMonthsBetween(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		want  int
	}{
		{
			name:  "same date is zero",
			start: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
			want:  0,
		},
		{
			name:  "approximately 3 years is 36 months",
			start: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
			want:  36,
		},
		{
			name:  "sub-month (10 days) rounds to zero",
			start: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2020, 6, 11, 0, 0, 0, 0, time.UTC),
			want:  0,
		},
		{
			name:  "reversed (end before start) is zero (floored)",
			start: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			want:  0,
		},
		{
			name: "day-of-month boundary: start day 15, end day 10 — partial month not counted",
			// start=June 15 → end=July 10: end.Day(10) < start.Day(15) → not yet 1 full month
			start: time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2020, 7, 10, 0, 0, 0, 0, time.UTC),
			want:  0,
		},
		{
			name:  "day-of-month boundary: start day 15, end day 15 exactly — counts",
			start: time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2020, 7, 15, 0, 0, 0, 0, time.UTC),
			want:  1,
		},
		{
			name:  "day-of-month boundary: start day 15, end day 16 — counts",
			start: time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2020, 7, 16, 0, 0, 0, 0, time.UTC),
			want:  1,
		},
		{
			name:  "exact 1 year",
			start: time.Date(2022, 3, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC),
			want:  12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MonthsBetween(tc.start, tc.end)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// UnavailableTenure
// ---------------------------------------------------------------------------

func TestUnavailableTenure(t *testing.T) {
	t.Parallel()
	got := UnavailableTenure("mysource", "some reason")
	assert.False(t, got.Available, "Available must be false")
	assert.Equal(t, "mysource", got.Source)
	assert.Equal(t, "some reason", got.Reason)
	assert.Equal(t, 0, got.Months, "Months must be zero for unavailable tenure")
	assert.False(t, got.Current, "Current must be false for unavailable tenure")
}

// ---------------------------------------------------------------------------
// Tenure.String
// ---------------------------------------------------------------------------

func TestTenure_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tenure Tenure
		want   string
	}{
		{
			name: "available current — years and months",
			tenure: Tenure{
				Available: true,
				Months:    38, // 3y 2m
				Current:   true,
			},
			want: "3y 2m (current)",
		},
		{
			name: "available non-current — years and months, no suffix",
			tenure: Tenure{
				Available: true,
				Months:    38,
				Current:   false,
			},
			want: "3y 2m",
		},
		{
			name: "available sub-year — months only",
			tenure: Tenure{
				Available: true,
				Months:    5,
				Current:   true,
			},
			want: "5m (current)",
		},
		{
			name: "available exact years — no month component",
			tenure: Tenure{
				Available: true,
				Months:    24,
				Current:   false,
			},
			want: "2y",
		},
		{
			name: "unavailable — renders reason",
			tenure: Tenure{
				Available: false,
				Reason:    "employment history not revealed",
			},
			want: "unavailable — employment history not revealed",
		},
		{
			name: "unavailable — different reason",
			tenure: Tenure{
				Available: false,
				Reason:    "breach data, no employment dates",
			},
			want: "unavailable — breach data, no employment dates",
		},
		{
			name:   "zero months available current",
			tenure: Tenure{Available: true, Months: 0, Current: true},
			want:   "0m (current)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.tenure.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
