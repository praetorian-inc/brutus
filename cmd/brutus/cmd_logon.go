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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
)

var logonCmd = &cobra.Command{
	Use:     "logon",
	Aliases: []string{"stickykeys", "sticky-keys", "utilman", "sethc", "winlogon", "accessibility"},
	Short:   "Detect Windows logon-screen backdoors (sticky keys, utilman)",
	Long: `Detect and interact with Windows logon-screen accessibility backdoors over RDP.

This subcommand automatically enables sticky keys and utilman backdoor
detection. The protocol defaults to RDP.

Modes:
  Detection:   brutus logon --target host:3389
  Exec:        brutus logon --target host:3389 --sticky-keys-exec "whoami"
  Web terminal: brutus logon --target host:3389 --sticky-keys-web

Use --experimental-ai to enable Vision API for more accurate backdoor
confirmation via screenshot analysis.`,
	Example: `  # Detect sticky keys and utilman backdoors (heuristic)
  brutus logon --target 10.0.0.50:3389

  # Vision API confirmation (more accurate)
  brutus logon --target 10.0.0.50:3389 --experimental-ai

  # Execute a command via sticky keys backdoor
  brutus logon --target 10.0.0.50:3389 --sticky-keys-exec "whoami"

  # Interactive web terminal via backdoor
  brutus logon --target 10.0.0.50:3389 --sticky-keys-web --sticky-keys-open

  # Pipeline mode with Nerva JSON (only RDP targets are tested)
  naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | brutus logon

  # Pipe plain targets (auto-fingerprinted, only RDP services scanned)
  echo "10.0.0.50:3389" | brutus logon

  # Pipe URI targets
  echo "rdp://10.0.0.50:3389" | brutus logon`,
	RunE: runLogon,
}

func init() {
	registerLogonFlags(logonCmd)
}

func runLogon(cmd *cobra.Command, args []string) error {
	base := buildBaseConfig(cmd)

	// AI config (logon-specific)
	if base.aiMode {
		llmCfg, aiErr := setupAIConfig(true, base.anthropicKey, base.perplexityKey)
		if aiErr != nil {
			return aiErr
		}
		base.llmConfig = llmCfg
	}

	// Logon mode defaults to RDP
	if base.protocolOverride == "" {
		base.protocolOverride = "rdp"
	}

	// In pipeline/fingerprint mode, only process RDP targets
	base.protocolFilter = func(protocol string) bool {
		return protocol == "rdp"
	}

	// Build logon-specific config
	lc := &logonConfig{
		stickyKeys:     true,
		stickyKeysExec: flagStickyKeysExec,
		stickyKeysWeb:  flagStickyKeysWeb,
		stickyKeysOpen: flagStickyKeysOpen,
		noUtilman:      flagNoUtilman,
	}

	rc := &runConfig{baseConfigOptions: base, logon: lc}

	useStdin := detectStdinMode(flagTarget, flagTargetsFile)

	// Set up output writer before banner check so --output can imply --json.
	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	// Show banner
	if shouldShowBanner(flagJSON, useStdin, flagQuiet, base.useColor) {
		printBanner(base.useColor)
	}

	// Determine if this is detection mode (no exec or web) vs interactive
	isDetectMode := lc.stickyKeysExec == "" && !lc.stickyKeysWeb

	if isDetectMode {
		// Scan/detection mode
		var scanResults []brutus.Result
		var hasSuccess bool

		switch {
		case useStdin:
			scanResults, hasSuccess = runScanFromStdin(rc)
		case flagTargetsFile != "":
			targetsList, loadErr := brutusinput.LoadTargetsFromFile(flagTargetsFile)
			if loadErr != nil {
				return loadErr
			}
			if len(targetsList) == 0 {
				return fmt.Errorf("targets file %q has no targets", flagTargetsFile)
			}
			scanResults, hasSuccess = runLogonFingerprint(targetsList, rc)
		default:
			if flagTarget == "" {
				return fmt.Errorf("--target is required (or pipe targets to stdin, or use --targets-file)")
			}
			scanResults, hasSuccess = runScanSingleTarget(flagTarget, rc)
		}

		if flagJSON {
			outputScanJSONL(jsonWriter, scanResults)
		} else {
			outputScanHuman(scanResults, base.useColor)
		}

		if !hasSuccess {
			return errNoSuccess
		}
		return nil
	}

	// Interactive modes (exec or web) require a single target
	if flagTarget == "" {
		return fmt.Errorf("--target is required for interactive sticky keys modes")
	}

	results, hasSuccess := runStickyKeysInteractive(flagTarget, rc)
	if flagJSON {
		outputScanJSONL(jsonWriter, results)
	} else {
		outputScanHuman(results, base.useColor)
	}

	if !hasSuccess {
		return errNoSuccess
	}
	return nil
}

// runLogonFingerprint fingerprints targets with Nerva and runs logon-screen
// detection on any discovered RDP services.
func runLogonFingerprint(targets []string, base *runConfig) ([]brutus.Result, bool) {
	stop, services, ok := fingerprintTargets(targets, base)
	if !ok {
		return nil, false
	}
	defer stop()

	var allResults []brutus.Result
	hasSuccess := false

	for i := range services {
		nrv := brutusinput.ServiceToNervaResult(&services[i])
		protocol := brutusinput.MapServiceToProtocol(nrv.Protocol)
		if protocol != "rdp" {
			logVerbose(base.verbose, "skipping %s:%d - not RDP (detected: %s)", nrv.IP, nrv.Port, nrv.Protocol)
			continue
		}

		results, success := runScanSingleTarget(nrv.TargetAddr(), base)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}
	}

	return allResults, hasSuccess
}
