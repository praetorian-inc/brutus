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
	"fmt"
	"time"
)

// Tenure describes how long a person has held their CURRENT role, derived from
// real source dates. It carries provenance (Source) and date granularity
// (Precision) rather than a High/Med/Low rollup — the consuming platform
// computes any confidence rollup itself. When the source carries no employment
// dates, Available is false and Reason explains why (no fabrication).
type Tenure struct {
	Available bool   // true only when derived from real source dates
	Months    int    // whole months in the current role
	Current   bool   // tenure reflects an ongoing role
	Source    string // provenance, e.g. "apollo:employment_history"
	Precision string // "day"|"month"|"year" granularity of the dates used
	Reason    string // when !Available: why (no fabrication)
}

// ParseFlexibleDate parses an employment date string at whatever granularity the
// source provides, returning the parsed time (in UTC), the precision of the
// input ("day", "month", or "year"), and ok=false for empty or unparseable
// input. Accepted forms: "2006-01-02" (day), "2006-01" (month), "2006" (year).
func ParseFlexibleDate(s string) (t time.Time, precision string, ok bool) {
	if s == "" {
		return time.Time{}, "", false
	}
	for _, f := range []struct {
		layout    string
		precision string
	}{
		{"2006-01-02", "day"},
		{"2006-01", "month"},
		{"2006", "year"},
	} {
		if parsed, err := time.ParseInLocation(f.layout, s, time.UTC); err == nil {
			return parsed, f.precision, true
		}
	}
	return time.Time{}, "", false
}

// MonthsBetween returns the number of whole calendar months elapsed from start
// to end, floored at 0. A partial trailing month (end's day-of-month not yet
// reached) does not count.
func MonthsBetween(start, end time.Time) int {
	if !end.After(start) {
		return 0
	}
	months := int(end.Year()-start.Year())*12 + int(end.Month()) - int(start.Month())
	if end.Day() < start.Day() {
		months--
	}
	if months < 0 {
		return 0
	}
	return months
}

// UnavailableTenure builds a Tenure marked unavailable, carrying the provenance
// source and the reason no tenure could be derived. It never fabricates dates.
func UnavailableTenure(source, reason string) Tenure {
	return Tenure{Available: false, Source: source, Reason: reason}
}

// String renders a human-readable tenure. Available tenures render as years and
// months ("3y 2m", or "<n>m" when under a year), with " (current)" appended for
// ongoing roles. Unavailable tenures render as "unavailable — <reason>".
func (t Tenure) String() string {
	if !t.Available {
		return "unavailable — " + t.Reason
	}

	years := t.Months / 12
	months := t.Months % 12

	var span string
	switch {
	case years > 0 && months > 0:
		span = fmt.Sprintf("%dy %dm", years, months)
	case years > 0:
		span = fmt.Sprintf("%dy", years)
	default:
		span = fmt.Sprintf("%dm", months)
	}

	if t.Current {
		return span + " (current)"
	}
	return span
}
