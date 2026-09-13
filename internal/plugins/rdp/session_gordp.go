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

// stickyKeysShiftPresses is how many times Shift is tapped to trigger sticky
// keys. Five is what Windows requires.
const stickyKeysShiftPresses = 5

// shiftTapInterval is the pause between Shift press and release, and between
// taps. Windows ignores presses delivered faster than a human could type.
const shiftTapInterval = 50 * time.Millisecond

// triggerFunc sends whatever keystrokes provoke the behaviour under test.
type triggerFunc func(ctx context.Context, sess rdpSession) error

// runBackendSession pumps a session to a settled baseline, fires a trigger, then
// pumps again and captures the response.
//
// It is the backend-independent form of runSession and runUtilmanSession, which
// differ only in their trigger. Returning both frames plus stabilized keeps the
// contract the analysis layer already expects.
//
//nolint:gocritic // cohesive multi-return matching the existing WASM path's shape
func (p *Plugin) runBackendSession(ctx context.Context, sess rdpSession, trigger triggerFunc,
	timeout time.Duration, budget SettleBudget, diag *sessionDiag) (baselineRGBA, responseRGBA []byte,
	outWidth, outHeight uint32, stabilized bool, err error) {

	width, height := sess.Size()

	// Settle the baseline before triggering. A host still initializing ("Please
	// wait for the Local Session Manager") has not painted its logon screen yet,
	// and triggering now would difference the response against a half-painted
	// baseline.
	baselineStable, pumpErr := pumpBackend(ctx, sess, timeout, budget, diag)
	if pumpErr != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("pump baseline: %w", pumpErr)
	}

	baseline, err := sess.Frame(ctx)
	if err != nil {
		return nil, nil, 0, 0, false, fmt.Errorf("capture baseline: %w", err)
	}

	if err := trigger(ctx, sess); err != nil {
		return nil, nil, 0, 0, false, err
	}

	// A dead sleep before pumping: the triggered process needs time to start and
	// paint before there is anything to observe.
	time.Sleep(budget.postKeystrokeWait)
	responseStable, pumpErr := pumpBackend(ctx, sess, timeout, budget, diag)

	// Choose the frame to analyse. A pump that errored means the session is
	// gone, and a torn-down framebuffer reads as a perfectly black screen: that
	// differences against the baseline as a dramatic change and would fabricate
	// a backdoor. Prefer the last frame seen while the session was alive, and
	// fall back to the baseline, which analyses as "no change" and is mapped to
	// indeterminate rather than to a positive.
	response, err := backendResponseFrame(ctx, sess, diag, baseline, pumpErr)
	if err != nil {
		return nil, nil, 0, 0, false, err
	}

	// Trust a "clean" reading only when both phases settled; otherwise
	// stabilizedVerdict downgrades it to indeterminate.
	return baseline, response, width, height, baselineStable && responseStable, nil
}

// backendResponseFrame picks the frame to analyse after the response pump.
//
// It mirrors responseFrame in the WASM path, and exists for the same reason: a
// capture from a torn-down session succeeds and returns black pixels, so a
// failed pump must never fall through to a live capture.
func backendResponseFrame(ctx context.Context, sess rdpSession, diag *sessionDiag,
	baseline []byte, pumpErr error) ([]byte, error) {

	if pumpErr == nil && !sess.Terminated() {
		frame, err := sess.Frame(ctx)
		if err != nil {
			return nil, fmt.Errorf("capture response: %w", err)
		}
		return frame, nil
	}

	// The session died. Use the newest frame observed while it was alive, so a
	// payload that painted and only then dropped the session is still detected.
	if diag != nil && diag.lastFrame != nil {
		return diag.lastFrame, nil
	}

	// Nothing was observed after the trigger. The baseline analyses as "no
	// change", which stabilizedVerdict maps to indeterminate: a rerun, never a
	// false positive and never a false negative that hides a finding.
	return baseline, nil
}

// triggerStickyKeys taps Shift five times, the sequence Windows treats as a
// request to enable sticky keys. On a host whose sethc.exe has been replaced,
// that launches the replacement instead.
func triggerStickyKeys(ctx context.Context, sess rdpSession) error {
	for i := 0; i < stickyKeysShiftPresses; i++ {
		if err := sess.SendKey(ctx, leftShiftScancode, true); err != nil {
			return fmt.Errorf("send shift press %d: %w", i+1, err)
		}
		time.Sleep(shiftTapInterval)
		if err := sess.SendKey(ctx, leftShiftScancode, false); err != nil {
			return fmt.Errorf("send shift release %d: %w", i+1, err)
		}
		time.Sleep(shiftTapInterval)
	}
	return nil
}

// triggerUtilman presses Win+U, which launches the Utility Manager. On a host
// whose utilman.exe has been replaced, that launches the replacement.
//
// The keys are released in reverse order: releasing Win before U can leave the
// server believing a key is still held.
func triggerUtilman(ctx context.Context, sess rdpSession) error {
	if err := sess.SendKey(ctx, leftWinScancode, true); err != nil {
		return fmt.Errorf("send win press: %w", err)
	}
	time.Sleep(shiftTapInterval)
	if err := sess.SendKey(ctx, uKeyScancode, true); err != nil {
		return fmt.Errorf("send u press: %w", err)
	}
	time.Sleep(shiftTapInterval)
	if err := sess.SendKey(ctx, uKeyScancode, false); err != nil {
		return fmt.Errorf("send u release: %w", err)
	}
	time.Sleep(shiftTapInterval)
	if err := sess.SendKey(ctx, leftWinScancode, false); err != nil {
		return fmt.Errorf("send win release: %w", err)
	}
	return nil
}
