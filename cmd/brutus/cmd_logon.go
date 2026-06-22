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
	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

var logonCmd = &cobra.Command{
	Use:     "logon",
	Aliases: []string{"winlogon"},
	Short:   "Detect Windows logon-screen backdoors (runs both sticky keys and utilman)",
	Long: `Detect and interact with Windows logon-screen accessibility backdoors over RDP.

This subcommand runs BOTH the sticky keys and utilman backdoor checks to answer
"does this host have a logon backdoor?". To run a single check on a clean screen
(reliable per-binary attribution), use the dedicated subcommands instead:

  brutus stickykeys --target host:3389   # sticky-keys only
  brutus utilman    --target host:3389   # utilman only

The protocol defaults to RDP.

Modes:
  Detection:    brutus logon --target host:3389
  Exec:         brutus logon --target host:3389 --exec "whoami"
  Web terminal: brutus logon --target host:3389 --web

Use --experimental-ai to enable Vision API for more accurate backdoor
confirmation via screenshot analysis.`,
	Example: `  # Detect sticky keys and utilman backdoors (heuristic)
  brutus logon --target 10.0.0.50:3389

  # Vision API confirmation (more accurate)
  brutus logon --target 10.0.0.50:3389 --experimental-ai

  # Execute a command via detected backdoor
  brutus logon --target 10.0.0.50:3389 --exec "whoami"

  # Interactive web terminal via backdoor
  brutus logon --target 10.0.0.50:3389 --web --open

  # Pipeline mode with Nerva JSON (only RDP targets are tested)
  naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | brutus logon

  # Pipe plain targets (auto-fingerprinted, only RDP services scanned)
  echo "10.0.0.50:3389" | brutus logon

  # Pipe URI targets
  echo "rdp://10.0.0.50:3389" | brutus logon

  # Import targets from nmap XML scan (only RDP services tested)
  brutus logon --nmap-file scan.xml`,
	RunE: runLogon,
}

// stickykeysCmd runs only the sticky-keys check on a clean logon screen, giving
// reliable per-binary attribution (no preceding check, so no contamination).
var stickykeysCmd = &cobra.Command{
	Use:     "stickykeys",
	Aliases: []string{"sticky-keys", "sethc"},
	Short:   "Detect the Windows sticky-keys (sethc.exe) logon backdoor only",
	Long: `Detect the Windows sticky-keys logon-screen backdoor (sethc.exe) over RDP.

Unlike "brutus logon" (which runs both checks), this runs ONLY the sticky-keys
check on a clean screen, so a positive result is reliably attributable to the
sethc.exe backdoor. The protocol defaults to RDP.`,
	Example: `  # Detect the sticky-keys backdoor only
  brutus stickykeys --target 10.0.0.50:3389

  # Vision API confirmation (more accurate)
  brutus stickykeys --target 10.0.0.50:3389 --experimental-ai`,
	RunE: runStickykeys,
}

// utilmanCmd runs only the utilman check on a clean logon screen.
var utilmanCmd = &cobra.Command{
	Use:     "utilman",
	Aliases: []string{"accessibility", "ease-of-access"},
	Short:   "Detect the Windows utilman (Ease of Access) logon backdoor only",
	Long: `Detect the Windows utilman logon-screen backdoor (utilman.exe / Ease of Access)
over RDP.

Unlike "brutus logon" (which runs both checks), this runs ONLY the utilman check
on a clean screen, so a positive result is reliably attributable to the utilman
backdoor. The protocol defaults to RDP.`,
	Example: `  # Detect the utilman backdoor only
  brutus utilman --target 10.0.0.50:3389

  # Vision API confirmation (more accurate)
  brutus utilman --target 10.0.0.50:3389 --experimental-ai`,
	RunE: runUtilman,
}

func init() {
	registerLogonFlags(logonCmd)
	registerLogonFlags(stickykeysCmd)
	registerLogonFlags(utilmanCmd)
}

// runLogon runs the combined sticky-keys + utilman detection (CheckBoth).
func runLogon(cmd *cobra.Command, args []string) error {
	return runLogonChecks(cmd, logon.CheckBoth)
}

// runStickykeys runs only the sticky-keys check.
func runStickykeys(cmd *cobra.Command, args []string) error {
	return runLogonChecks(cmd, logon.CheckStickyKeys)
}

// runUtilman runs only the utilman check.
func runUtilman(cmd *cobra.Command, args []string) error {
	return runLogonChecks(cmd, logon.CheckUtilman)
}

// runLogonChecks is the shared body for the logon family of commands. checks
// selects which logon-screen backdoor check(s) the scan path runs.
func runLogonChecks(cmd *cobra.Command, checks logon.Check) error {
	if flagOpen && !flagWeb {
		return fmt.Errorf("--open requires --web (starts a web terminal and opens the browser)")
	}

	base := buildBaseConfig(cmd)
	base.checks = checks

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
		execCmd:     flagExec,
		webTerminal: flagWeb,
		openBrowser: flagOpen,
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
	isDetectMode := lc.execCmd == "" && !lc.webTerminal

	if isDetectMode {
		// Scan/detection mode
		var scanResults []brutus.Result
		var hasSuccess bool

		// Validate mutual exclusivity of target sources.
		if err := validateTargetSources(useStdin); err != nil {
			return err
		}

		switch {
		case useStdin:
			scanResults, hasSuccess = runScanFromStdin(rc)
		case flagNmapFile != "":
			scanResults, hasSuccess = runScanFromNmapFile(rc)
		case flagMasscanFile != "":
			scanResults, hasSuccess = runScanFromMasscanFile(rc)
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

		return scanExitError(scanResults, hasSuccess)
	}

	// Interactive modes (exec/web) drive the sticky-keys backdoor, so they are
	// not valid for the utilman-only check: silently executing via the wrong
	// vector would be a footgun. Detection mode for utilman is unaffected.
	if checks == logon.CheckUtilman && (flagExec != "" || flagWeb) {
		return fmt.Errorf("--exec/--web are not supported for 'utilman' (interactive modes use the sticky-keys backdoor); use 'brutus stickykeys' or 'brutus logon'")
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

	return scanExitError(results, hasSuccess)
}

// scanExitError maps aggregated scan outcomes to the process exit error,
// following this precedence: a success (found backdoor) → nil (exit 0);
// otherwise any indeterminate result → errIndeterminate (exit 2);
// otherwise → errNoSuccess (exit 1).
func scanExitError(results []brutus.Result, hasSuccess bool) error {
	if hasSuccess {
		return nil
	}
	for i := range results {
		if results[i].Indeterminate {
			return errIndeterminate
		}
	}
	return errNoSuccess
}

// runLogonFingerprint fingerprints targets with Nerva and runs logon-screen
// detection on any discovered RDP services.
func runLogonFingerprint(targets []string, base *runConfig) ([]brutus.Result, bool) {
	stop, services, ok := fingerprintTargets(targets, base)
	if !ok {
		return nil, false
	}
	defer stop()

	var scanTargets []string
	for i := range services {
		nrv := brutusinput.ServiceToNervaResult(&services[i])
		protocol := brutusinput.MapServiceToProtocol(nrv.Protocol)
		if protocol != "rdp" {
			logVerbose(base.verbose, "skipping %s:%d - not RDP (detected: %s)", nrv.IP, nrv.Port, nrv.Protocol)
			continue
		}
		scanTargets = append(scanTargets, nrv.TargetAddr())
	}

	return runScanTargetsConcurrent(scanTargets, base)
}
