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

// Package logon provides Windows logon-screen backdoor detection and interaction
// for the "brutus logon" subcommand. It wraps the internal RDP plugin.
package logon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
)

// BackdoorType indicates which logon-screen backdoor to target.
type BackdoorType = rdp.BackdoorType

const (
	BackdoorStickyKeys BackdoorType = rdp.BackdoorStickyKeys
	BackdoorUtilman    BackdoorType = rdp.BackdoorUtilman
)

// DetectBackdoors runs sticky keys and utilman detection against a single RDP
// target and returns one Finding per check performed.
//
// Every return path yields a Finding whose Verdict is set, including the states
// that mean the host was never scanned (nla_required, unreachable, canceled),
// so a caller never has to infer "not scanned" from an empty or clean-looking
// result. Use AnyPositive to ask whether a backdoor was found.
//
// A process-wide decode slot (admission.go) is acquired before any dial so that
// queued hosts spend zero pump budget; the slot bounds concurrent WASM-decode
// sessions independently of the host errgroup's --threads limit. The slot is
// held across retries: a retrying host is exactly the one that needs CPU, and
// re-queueing it risks unbounded latency.
//
// Retries are keyed on the rerun-eligible outcomes only. A positive verdict and
// a stabilized clean render are both final and are returned immediately;
// retrying a positive would risk masking a real backdoor.
func DetectBackdoors(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool,
	maxRetries int, checks Check, proxyURL string, noNLAProbe bool, fast bool) []Finding {

	// STAGE 1 — pre-WASM NLA probe (no decode slot, runs at full --threads).
	// Only an explicit HYBRID selection / HYBRID_REQUIRED_BY_SERVER skips WASM;
	// every other outcome (including probe errors) falls through to detection.
	// The dial and the single-RTT nego read both use connectTimeout: a reachable
	// host answers in ~1 RTT, so connectTimeout is the right read budget and
	// never harms reachable hosts.
	if !noNLAProbe {
		switch nlaProbe(ctx, target, connectTimeout, connectTimeout, proxyURL) {
		case rdp.NegoNLARequired:
			// Terminal, non-retryable: return BEFORE acquiring a decode slot.
			return NLARequiredResults(target, checks)
		case rdp.NegoUnreachable:
			// Terminal, non-retryable: return BEFORE acquiring a decode slot.
			return UnreachableResults(target, checks)
		case rdp.NegoProbeError, rdp.NegoScannable:
			// Fall through to the existing WASM path. The probe never skips on
			// uncertainty (cardinal rule).
		}
	}

	// STAGE 2 — existing decode-slot-gated WASM pipeline.
	if err := decodeSlots.Acquire(ctx, 1); err != nil {
		// Context canceled while queued: the host never ran, so it must read
		// as canceled, never silently clean.
		return CancelledResults(target, checks)
	}
	defer decodeSlots.Release(1)

	attempts := maxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			retryBackoff(ctx, attempt)
		}
		findings := runDetection(ctx, target, connectTimeout, timeout, aiMode, checks, fast)
		if AnyPositive(findings) || !AnyNeedsRerun(findings) || attempt == attempts-1 {
			return findings
		}
	}
	// attempts is always >= 1, so the loop's final iteration always returns;
	// this is unreachable and exists only to satisfy the compiler.
	panic("unreachable: DetectBackdoors loop must return")
}

// retryBackoff sleeps a capped exponential delay before a retry attempt,
// returning early if the context is canceled. attempt is 1-based.
func retryBackoff(ctx context.Context, attempt int) {
	const base = 100 * time.Millisecond
	const maxDelay = 2 * time.Second
	delay := base << (attempt - 1)
	if delay > maxDelay || delay <= 0 {
		delay = maxDelay
	}
	select {
	case <-time.After(delay):
	case <-ctx.Done():
	}
}

// InteractionMode identifies which operator-driven mode produced an
// InteractionResult.
type InteractionMode string

const (
	// InteractionExec ran a command through a detected backdoor.
	InteractionExec InteractionMode = "exec"
	// InteractionWebTerminal served an interactive session through a backdoor.
	InteractionWebTerminal InteractionMode = "web_terminal"
)

// InteractionResult is the outcome of an operator-driven interaction with a
// logon-screen backdoor.
//
// These modes use access rather than detect it, so they report their own shape
// and never a Finding: a Finding answers "does this host have a backdoor",
// while an interaction presumes the answer is already yes. Neither reports a
// brutus.Result — no credential is tested on either path, and the old shared
// type forced them to invent one ("(sticky-keys)" as a username).
type InteractionResult struct {
	// Target is the host:port interacted with.
	Target string
	// Mode is which interaction ran.
	Mode InteractionMode
	// Succeeded reports whether the interaction did what it set out to do:
	// for exec, that the backdoor was reached and the command ran; for the web
	// terminal, that the session was served to completion.
	Succeeded bool
	// Output is the command output, exec mode only.
	Output string
	// ScreenshotPath is where the post-exec frame was written when no text
	// output was recovered, exec mode only.
	ScreenshotPath string
	// Err is the failure that ended the interaction, if any.
	Err error
}

// ExecConfig holds parameters for sticky-keys command execution.
type ExecConfig struct {
	Target       string
	Timeout      time.Duration
	AIMode       bool
	AnthropicKey string
}

// RunExec connects to an RDP target, triggers the sticky keys backdoor, and
// executes a command.
func RunExec(ctx context.Context, cfg ExecConfig, command string) InteractionResult {
	result := InteractionResult{Target: cfg.Target, Mode: InteractionExec}

	var execAPIKey string
	if cfg.AIMode {
		execAPIKey = cfg.AnthropicKey
	}
	execResult := rdp.RunStickyKeysExec(ctx, cfg.Target, command, cfg.Timeout, execAPIKey)
	if execResult.Error != "" {
		result.Err = fmt.Errorf("%s", execResult.Error)
		return result
	}
	result.Succeeded = execResult.BackdoorDetected
	result.Output = execResult.Output
	result.ScreenshotPath = execResult.ScreenshotPath
	return result
}

// WebTerminalConfig holds parameters for the web terminal mode.
type WebTerminalConfig struct {
	Target      string
	Timeout     time.Duration
	OpenBrowser bool
}

// RunWebTerminal starts an interactive web terminal via the utilman backdoor.
func RunWebTerminal(ctx context.Context, cfg WebTerminalConfig) InteractionResult {
	result := InteractionResult{Target: cfg.Target, Mode: InteractionWebTerminal}

	err := rdp.RunWebTerminal(ctx, cfg.Target, cfg.Timeout, cfg.OpenBrowser, BackdoorUtilman)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		result.Err = err
		return result
	}
	result.Succeeded = true
	return result
}
