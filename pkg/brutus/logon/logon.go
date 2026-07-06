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
	"fmt"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// BackdoorType indicates which logon-screen backdoor to target.
type BackdoorType = rdp.BackdoorType

const (
	BackdoorStickyKeys BackdoorType = rdp.BackdoorStickyKeys
	BackdoorUtilman    BackdoorType = rdp.BackdoorUtilman
)

// DetectBackdoors runs sticky keys and utilman detection against a single RDP
// target. Returns results and whether any backdoor was found.
//
// A process-wide decode slot (admission.go) is acquired before any dial so that
// queued hosts spend zero pump budget; the slot bounds concurrent WASM-decode
// sessions independently of the host errgroup's --threads limit. The slot is
// held across retries: a retrying host is exactly the one that needs CPU, and
// re-queueing it risks unbounded latency.
//
// Retries are keyed on the INDETERMINATE outcome only. A found backdoor
// (hasSuccess) and a stabilized clean render are both final verdicts and are
// returned immediately; retrying a positive would risk masking a real backdoor.
func DetectBackdoors(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool,
	maxRetries int, checks Check, proxyURL string, noNLAProbe bool, fast bool) ([]brutus.Result, bool) {

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
			return NLARequiredResults(target, checks), false
		case rdp.NegoUnreachable:
			// Terminal, non-retryable: return BEFORE acquiring a decode slot.
			return UnreachableResults(target, checks), false
		case rdp.NegoProbeError, rdp.NegoScannable:
			// Fall through to the existing WASM path. The probe never skips on
			// uncertainty (cardinal rule).
		}
	}

	// STAGE 2 — existing decode-slot-gated WASM pipeline.
	if err := decodeSlots.Acquire(ctx, 1); err != nil {
		// Context canceled while queued: the host never ran, so it must read
		// as indeterminate, never silently clean.
		return CancelledResults(target), false
	}
	defer decodeSlots.Release(1)

	attempts := maxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			retryBackoff(ctx, attempt)
		}
		results, hasSuccess := runDetection(ctx, target, connectTimeout, timeout, aiMode, checks, fast)
		if hasSuccess || !anyIndeterminate(results) || attempt == attempts-1 {
			return results, hasSuccess
		}
	}
	// attempts is always >= 1, so the loop's final iteration always returns;
	// this is unreachable and exists only to satisfy the compiler.
	panic("unreachable: DetectBackdoors loop must return")
}

// anyIndeterminate reports whether any result could not produce a clean/dirty
// verdict (e.g. a CPU-starved render). Such hosts are eligible for retry.
func anyIndeterminate(results []brutus.Result) bool {
	for i := range results {
		if results[i].Indeterminate {
			return true
		}
	}
	return false
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

// ExecConfig holds parameters for sticky-keys command execution.
type ExecConfig struct {
	Target       string
	Timeout      time.Duration
	AIMode       bool
	AnthropicKey string
}

// RunExec connects to an RDP target, triggers the sticky keys backdoor,
// and executes a command. Returns a result and whether the backdoor was detected.
func RunExec(ctx context.Context, cfg ExecConfig, command string) (brutus.Result, bool) {
	result := brutus.Result{
		Protocol: "rdp",
		Target:   cfg.Target,
		Username: "(sticky-keys)",
	}

	var execAPIKey string
	if cfg.AIMode {
		execAPIKey = cfg.AnthropicKey
	}
	execResult := rdp.RunStickyKeysExec(ctx, cfg.Target, command, cfg.Timeout, execAPIKey)
	if execResult.Error != "" {
		result.Error = fmt.Errorf("%s", execResult.Error)
		return result, false
	}
	result.Success = execResult.BackdoorDetected
	if execResult.Output != "" {
		result.Banner = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, output:\n%s",
			execResult.BackdoorDetected, execResult.Output)
	} else {
		result.Banner = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, screenshot=%s",
			execResult.BackdoorDetected, execResult.ScreenshotPath)
	}
	return result, execResult.BackdoorDetected
}

// WebTerminalConfig holds parameters for the web terminal mode.
type WebTerminalConfig struct {
	Target      string
	Timeout     time.Duration
	OpenBrowser bool
}

// RunWebTerminal starts an interactive web terminal via the utilman backdoor.
// Returns a result and whether the session was successful.
func RunWebTerminal(ctx context.Context, cfg WebTerminalConfig) (brutus.Result, bool) {
	backdoorType := BackdoorUtilman
	username := "(utilman)"

	result := brutus.Result{
		Protocol: "rdp",
		Target:   cfg.Target,
		Username: username,
	}

	err := rdp.RunWebTerminal(ctx, cfg.Target, cfg.Timeout, cfg.OpenBrowser, backdoorType)
	if err != nil && err != http.ErrServerClosed {
		result.Error = err
		return result, false
	}
	result.Success = true
	result.Banner = "[INFO] Web terminal session ended"
	return result, true
}
