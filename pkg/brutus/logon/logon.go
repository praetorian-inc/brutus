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

// DetectBackdoors runs sticky keys (and optionally utilman) detection against
// a single RDP target. Returns results and whether any backdoor was found.
func DetectBackdoors(ctx context.Context, target string, timeout time.Duration, aiMode, noUtilman bool) ([]brutus.Result, bool) {
	noVision := !aiMode

	stickyResult := rdp.DetectStickyKeys(ctx, target, timeout, "(sticky-keys)", noVision)
	results := []brutus.Result{*stickyResult}
	hasSuccess := stickyResult.Success

	if !noUtilman {
		utilmanResult := rdp.DetectUtilman(ctx, target, timeout, "(utilman)", noVision)
		results = append(results, *utilmanResult)
		if utilmanResult.Success {
			hasSuccess = true
		}
	}

	return results, hasSuccess
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
	NoUtilman   bool
	OpenBrowser bool
}

// RunWebTerminal starts an interactive web terminal via the specified backdoor.
// Returns a result and whether the session was successful.
func RunWebTerminal(ctx context.Context, cfg WebTerminalConfig) (brutus.Result, bool) {
	backdoorType := BackdoorUtilman
	username := "(utilman)"
	if cfg.NoUtilman {
		backdoorType = BackdoorStickyKeys
		username = "(sticky-keys)"
	}

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
