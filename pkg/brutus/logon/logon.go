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
func DetectBackdoors(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool,
	maxRetries int, checks Check, proxyURL string, noNLAProbe bool, fast bool) []Finding {

	if !noNLAProbe {
		switch nlaProbe(ctx, target, connectTimeout, connectTimeout, proxyURL) {
		case rdp.NegoNLARequired:
			return NLARequiredResults(target, checks)
		case rdp.NegoUnreachable:
			return UnreachableResults(target, checks)
		case rdp.NegoProbeError, rdp.NegoScannable:
		}
	}

	if err := decodeSlots.Acquire(ctx, 1); err != nil {
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
	panic("unreachable: DetectBackdoors loop must return")
}

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

type InteractionMode string

const (
	InteractionExec        InteractionMode = "exec"
	InteractionWebTerminal InteractionMode = "web_terminal"
)

// InteractionResult is the outcome of an operator-driven interaction with a
// logon-screen backdoor.
type InteractionResult struct {
	Target         string
	Mode           InteractionMode
	Succeeded      bool
	Output         string
	ScreenshotPath string
	Err            error
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
