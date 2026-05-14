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

  # Pipeline mode (only RDP targets are tested)
  naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | brutus logon`,
	RunE: runLogon,
}

func init() {
	registerLogonFlags(logonCmd)
}

func runLogon(cmd *cobra.Command, args []string) error {
	baseConfig, err := buildConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	// Logon mode always enables sticky keys detection and defaults to RDP
	baseConfig.stickyKeys = true
	if baseConfig.protocolOverride == "" {
		baseConfig.protocolOverride = "rdp"
	}

	// In pipeline/fingerprint mode, only process RDP targets
	baseConfig.protocolFilter = func(protocol string) bool {
		return protocol == "rdp"
	}

	useStdin := detectStdinMode(flagNerva, flagTarget, flagFingerprint)

	// Show banner
	if shouldShowBanner(flagBanner, flagJSON, useStdin, flagQuiet, baseConfig.useColor) {
		printBanner(baseConfig.useColor)
	}

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	// Determine if this is detection mode (no exec or web) vs interactive
	isDetectMode := baseConfig.stickyKeysExec == "" && !baseConfig.stickyKeysWeb

	if isDetectMode {
		// Scan/detection mode
		var scanResults []brutus.Result
		var hasSuccess bool

		switch {
		case useStdin:
			scanResults, hasSuccess = runScanFromStdin(baseConfig)
		case flagFingerprint != "":
			// Fingerprint mode: scan discovered RDP targets
			targetsList, loadErr := brutus.LoadTargetsFromFile(flagFingerprint)
			if loadErr != nil {
				return loadErr
			}
			if len(targetsList) == 0 {
				return fmt.Errorf("fingerprint file %q has no targets", flagFingerprint)
			}
			scanResults, hasSuccess = runLogonFingerprint(targetsList, baseConfig)
		default:
			if flagTarget == "" {
				return fmt.Errorf("--target is required (or pipe nerva JSON to stdin, or use --fingerprint)")
			}
			scanResults, hasSuccess = runScanSingleTarget(flagTarget, baseConfig)
		}

		if flagJSON {
			outputScanJSONL(jsonWriter, scanResults)
		} else {
			outputScanHuman(scanResults, baseConfig.useColor)
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

	results, hasSuccess := runStickyKeysInteractive(flagTarget, "rdp", baseConfig)
	if flagJSON {
		outputScanJSONL(jsonWriter, results)
	} else {
		outputScanHuman(results, baseConfig.useColor)
	}

	if !hasSuccess {
		return errNoSuccess
	}
	return nil
}

// runLogonFingerprint fingerprints targets and runs logon-screen detection on discovered RDP services.
func runLogonFingerprint(targets []string, base *baseConfigOptions) ([]brutus.Result, bool) {
	// Reuse the fingerprint infrastructure but run scan instead of brute force.
	// We call runFromFingerprint with a modified config that has protocolFilter for RDP only.
	// However, since logon mode is scan-based (not brute-force), we handle it differently.

	// For now, use the stdin-based scan approach: fingerprint first, then scan each RDP target.
	// This is a simplified version that parses fingerprint results.
	var allResults []brutus.Result
	hasSuccess := false

	// Parse and scan each target that might be RDP
	for _, target := range targets {
		// Default: assume it could be RDP and try scanning directly
		results, success := runScanSingleTarget(target, base)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}
	}

	return allResults, hasSuccess
}
