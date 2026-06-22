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

package brutus

import (
	"strings"
	"time"
)

// Mode represents the aggressiveness tier for credential testing.
// It controls wordlist depth and performance tuning presets (threads,
// timeout, rate limit, jitter, max attempts, and retries).
type Mode string

const (
	// ModeCautious uses a minimal credential set, lower concurrency, and rate
	// limiting to avoid account lockouts. Safe for production environments.
	ModeCautious Mode = "cautious"

	// ModeDefault is the standard mode balancing coverage and safety.
	ModeDefault Mode = "default"

	// ModeAggressive uses the full credential set and higher concurrency
	// for maximum coverage. Use in lab/CTF environments.
	ModeAggressive Mode = "aggressive"
)

// ModePresets holds the performance tuning values associated with a Mode.
type ModePresets struct {
	Threads     int
	Timeout     time.Duration
	RateLimit   float64
	Jitter      time.Duration
	MaxAttempts int
	MaxRetries  int
}

// NormalizeMode converts a user-supplied string to a validated [Mode] constant.
// Unrecognized values fall back to [ModeDefault].
func NormalizeMode(s string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeCautious:
		return ModeCautious
	case ModeAggressive:
		return ModeAggressive
	default:
		return ModeDefault
	}
}

// ValidMode returns true if s is a recognized mode string.
func ValidMode(s string) bool {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeCautious, ModeDefault, ModeAggressive:
		return true
	default:
		return false
	}
}

// Presets returns the performance tuning values for this mode.
func (m Mode) Presets() ModePresets {
	switch m {
	case ModeCautious:
		return ModePresets{
			Threads:     5,
			Timeout:     15 * time.Second,
			RateLimit:   2,
			Jitter:      500 * time.Millisecond,
			MaxAttempts: 3,
			MaxRetries:  1,
		}
	case ModeAggressive:
		return ModePresets{
			Threads:     20,
			Timeout:     10 * time.Second,
			RateLimit:   0, // unlimited
			Jitter:      0,
			MaxAttempts: 0, // unlimited
			MaxRetries:  3,
		}
	default: // ModeDefault
		return ModePresets{
			Threads: 10,
			// With admission control bounding concurrent WASM decode, the pump
			// budget is spent on real CPU rather than starvation, so 10s is
			// sufficient for the logon render; no value change needed.
			Timeout:     10 * time.Second,
			RateLimit:   0, // unlimited
			Jitter:      0,
			MaxAttempts: 0, // unlimited
			MaxRetries:  2,
		}
	}
}
