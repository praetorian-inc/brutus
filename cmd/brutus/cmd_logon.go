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

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

var logonCmd = &cobra.Command{
	Use:   "logon",
	Short: "Detect Windows logon-screen backdoors (runs both sticky keys and utilman)",
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
	Use:   "stickykeys",
	Short: "Detect the Windows sticky-keys (sethc.exe) logon backdoor only",
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
	Use:   "utilman",
	Short: "Detect the Windows utilman (Ease of Access) logon backdoor only",
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
	for _, cmd := range []*cobra.Command{logonCmd, stickykeysCmd, utilmanCmd} {
		registerLogonFlags(cmd)
		guardLogonTimeoutFlag(cmd)
	}
}

// guardLogonTimeoutFlag hard-renames the logon-family settle deadline from
// --timeout to --scan-timeout. The shared --timeout flag is a persistent flag on
// rootCmd that every command inherits, so it cannot simply be unregistered here
// without breaking the non-logon commands that legitimately use it. Two pieces:
//
//   - Hard error (the must-have): a PreRunE rejects any explicit --timeout on
//     these commands with guidance. PreRunE is used rather than
//     PersistentPreRunE so it does not override rootCmd's PersistentPreRunE,
//     which still validates --mode for the logon family.
//   - Help hiding (best-effort): the inherited --timeout flag is hidden from
//     this command's --help so only --scan-timeout/--connect-timeout surface.
//     The flag object is shared with the root command, so toggling Hidden
//     globally would also hide it from non-logon help. We instead flip Hidden
//     only for the duration of this command's own help render via SetHelpFunc,
//     restoring it immediately after so other commands are unaffected.
func guardLogonTimeoutFlag(cmd *cobra.Command) {
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		if c.Flags().Changed("timeout") {
			return fmt.Errorf("--timeout is not valid here; use --scan-timeout (settle deadline) and/or --connect-timeout (TCP connect)")
		}
		return nil
	}

	defaultHelp := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		if tf := c.InheritedFlags().Lookup("timeout"); tf != nil {
			tf.Hidden = true
			defer func() { tf.Hidden = false }()
		}
		defaultHelp(c, args)
	})
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

	base, err := buildBaseConfig(cmd)
	if err != nil {
		return err
	}
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

		// A pump phase can only settle after rdp.MinViableTimeout of evidence; a
		// --scan-timeout below that floor forces every host to INDETERMINATE (and
		// a wasteful retry) for zero real signal. Warn (don't error) so existing
		// scripts keep working.
		if base.timeout < rdp.MinViableTimeout {
			warnMsg(base.useColor, "--scan-timeout %s is below the detection settle floor (%s); every host will return INDETERMINATE. Use --scan-timeout 15s or higher for reliable results.",
				base.timeout, rdp.MinViableTimeout)
		}

		// Validate mutual exclusivity of target sources.
		if err := validateTargetSources(useStdin); err != nil {
			return err
		}

		switch {
		case useStdin:
			scanResults, _ = runScanFromStdin(rc)
		case flagNmapFile != "":
			scanResults, _ = runScanFromNmapFile(rc)
		case flagMasscanFile != "":
			scanResults, _ = runScanFromMasscanFile(rc)
		case flagTargetsFile != "":
			targetsList, loadErr := brutusinput.LoadTargetsFromFile(flagTargetsFile)
			if loadErr != nil {
				return loadErr
			}
			if len(targetsList) == 0 {
				return fmt.Errorf("targets file %q has no targets", flagTargetsFile)
			}
			scanResults, _ = runLogonFingerprint(targetsList, rc)
		default:
			if flagTarget == "" {
				return fmt.Errorf("--target is required (or pipe targets to stdin, or use --targets-file)")
			}
			scanResults, _ = runScanSingleTarget(flagTarget, rc)
		}

		if flagJSON {
			outputScanJSONL(jsonWriter, scanResults)
		} else {
			outputScanHuman(scanResults, base.useColor)
		}

		return scanExitError(scanResults)
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

	results, _ := runStickyKeysInteractive(flagTarget, rc)
	if flagJSON {
		outputScanJSONL(jsonWriter, results)
	} else {
		outputScanHuman(results, base.useColor)
	}

	return scanExitError(results)
}

// scanExitError maps aggregated scan outcomes to the process exit error for the
// logon family of scans. A completed scan is a success whether or not a backdoor
// was found, so a clean/nothing-found result is NOT an error (exit 0). Any
// indeterminate result takes precedence and yields errIndeterminate (exit 2) so
// the operator knows to rerun the affected hosts.
func scanExitError(results []brutus.Result) error {
	for i := range results {
		if results[i].Indeterminate {
			return errIndeterminate
		}
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
