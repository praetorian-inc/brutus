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

package rdp

import (
	"context"
	"fmt"
	"time"
)

// pumpBackend drives a session until its framebuffer stabilizes, or until the
// deadline expires.
//
// It is the backend-independent half of the original pumpSession: the same
// quiet-window, minimum-pump and noise-floor rules, expressed against the
// rdpSession interface so both the WASM and native backends settle identically.
// Keeping one implementation matters more than it looks — these thresholds are
// what separate "the host is still painting" from "the screen is stable", and a
// second copy would drift.
//
// Returns stabilized=true only once budget.minPump has elapsed AND the
// framebuffer has been quiet for budget.quietWindow. A deadline reached while
// frames were still changing is not an error: it returns false, and
// stabilizedVerdict downgrades a "clean" reading to indeterminate on that basis.
func pumpBackend(ctx context.Context, sess rdpSession, timeout time.Duration,
	budget SettleBudget, diag *sessionDiag) (stabilized bool, err error) {

	// diag.lastFrame belongs to this pump. runSession shares one sessionDiag
	// across the baseline and response phases, and a baseline-phase frame is not
	// a post-trigger observation: carried over, a response pump that errored
	// before observing anything would hand responseFrame a pre-trigger frame to
	// difference against the baseline, reading as a change the trigger never
	// caused.
	if diag != nil {
		diag.lastFrame = nil
	}

	width, height := sess.Size()
	deadline := time.Now().Add(timeout)

	var prevFrame []byte
	start := time.Now()
	lastChange := start

	for time.Now().Before(deadline) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}

		// A read timeout is reported as (false, nil), so wall-clock time
		// advances without resetting the quiet window. That is what lets quiet
		// time accumulate across the short pauses in RDP's bursty painting.
		updated, stepErr := sess.Step(ctx, budget.readDeadline)
		if stepErr != nil {
			return false, stepErr
		}

		if sess.Terminated() {
			// The session is gone. Its framebuffer now reads as a perfectly
			// black screen, which differences against the baseline as a dramatic
			// change and would fabricate a backdoor finding, so this is reported
			// as an error and responseFrame falls back to the last live frame.
			if diag != nil {
				diag.terminated = true
				diag.reason = "server ended the session"
			}
			return false, fmt.Errorf("session terminated during pump")
		}

		if !updated {
			continue
		}

		frame, capErr := sess.Frame(ctx)
		if capErr != nil {
			// A capture failure is not fatal to the pump; the next update may
			// succeed and the deadline still bounds the loop.
			continue
		}

		// Sub-threshold change (a blinking cursor, a spinner) must not reset the
		// quiet window, or a host showing a caret never settles and every scan
		// of it reports indeterminate.
		if prevFrame == nil || !framesQuiet(prevFrame, frame, width, height, budget) {
			lastChange = time.Now()
		}
		prevFrame = frame

		// Retain the newest frame seen while the session was alive: if the
		// server tears the session down later, this is the only trustworthy view
		// of the screen.
		if diag != nil {
			diag.lastFrame = frame
		}

		if settled(start, lastChange, time.Now(), budget) {
			return true, nil
		}
	}

	// The deadline is not fatal. stabilized stays false, which downstream turns
	// a clean reading into indeterminate rather than trusting it.
	return false, nil
}
