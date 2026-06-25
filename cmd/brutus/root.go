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
	"io"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

// errNoSubcommand is returned when the root command is invoked without a subcommand.
var errNoSubcommand = fmt.Errorf("a subcommand is required (creds, web, snmp, badkeys, logon, enum)")

var rootCmd = &cobra.Command{
	Use:   "brutus",
	Short: "Brutus - Et tu, Brute?",
	Long: `Brutus - Et tu, Brute?
Modern credential auditing tool for network services, web panels, and Windows logon screens.

Subcommands:
  creds    Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)
  web      Audit HTTP/web panel credentials (Basic Auth, form login, AI-powered)
  snmp     Test SNMP community strings against targets
  badkeys  Test known weak/compromised SSH keys against targets
  logon    Detect Windows logon-screen backdoors (sticky keys, utilman)
  enum     Enumerate email accounts against SaaS services (M365, Google, etc.)

All subcommands accept targets via stdin (one per line, formats can be mixed):
  Nerva JSON:  {"ip":"10.0.0.1","port":22,"protocol":"ssh"}
  URI scheme:  ssh://192.168.1.1:22, rdp://10.0.0.50:3389
  Bare target: 192.168.1.1:22 (auto-fingerprinted with Nerva)

Targets can also be imported from scan tool output:
  Nmap XML:     brutus creds --nmap-file scan.xml
  Masscan JSON: brutus creds --masscan-file scan.json`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runRoot,
}

func init() {
	registerSharedFlags(rootCmd)
	registerRootFlags(rootCmd)

	// Validate shared flags before any subcommand runs.
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// SNMP has its own tier names (extended, full) that predate the global
		// mode system. Skip strict validation for SNMP so legacy modes pass
		// through to ConfigureSNMP which handles the mapping.
		if cmd.Name() != "snmp" && !brutus.ValidMode(flagMode) {
			return fmt.Errorf("invalid --mode %q (valid: cautious, default, aggressive)", flagMode)
		}
		return nil
	}

	rootCmd.AddCommand(credsCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(snmpCmd)
	rootCmd.AddCommand(badkeysCmd)
	rootCmd.AddCommand(logonCmd)
	rootCmd.AddCommand(stickykeysCmd)
	rootCmd.AddCommand(utilmanCmd)
	rootCmd.AddCommand(enumCmd)
}

// runRoot handles the root command (no subcommand). It only supports --version;
// everything else requires a subcommand.
func runRoot(cmd *cobra.Command, args []string) error {
	if flagVersion {
		useColor := isColorEnabled(flagNoColor)
		printVersion(useColor)
		return nil
	}

	return errNoSubcommand
}

// runSubcommand is the shared execution path for creds, web, and logon subcommands.
// It handles mode dispatch (single target, targets-file, fingerprint, stdin) with
// the protocol filtering and overrides already applied to baseConfig by the caller.
func runSubcommand(cmd *cobra.Command, baseConfig *runConfig) error {
	useStdin := detectStdinMode(flagTarget, flagTargetsFile)

	// Validate mutual exclusivity of target sources.
	if err := validateTargetSources(useStdin); err != nil {
		return err
	}

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
	if shouldShowBanner(flagJSON, useStdin, flagQuiet, baseConfig.useColor) {
		printBanner(baseConfig.useColor)
	}

	var allResults []brutus.Result
	var hasSuccess bool

	protocol := baseConfig.protocolOverride

	switch {
	case useStdin:
		allResults, hasSuccess = runFromStdin(baseConfig, flagJSON)

	case flagNmapFile != "":
		allResults, hasSuccess = runFromNmapFile(baseConfig, flagJSON)

	case flagMasscanFile != "":
		allResults, hasSuccess = runFromMasscanFile(baseConfig, flagJSON)

	case flagTargetsFile != "":
		targetsList, err := brutusinput.LoadTargetsFromFile(flagTargetsFile)
		if err != nil {
			return err
		}
		if len(targetsList) == 0 {
			return fmt.Errorf("targets file %q has no targets after stripping comments and blank lines", flagTargetsFile)
		}
		// If --protocol is set, use targets directly; otherwise fingerprint with Nerva
		if baseConfig.protocolOverride != "" {
			allResults, hasSuccess = runFromTargetsFile(targetsList, baseConfig, flagJSON)
		} else {
			allResults, hasSuccess = runFromFingerprint(targetsList, baseConfig, flagJSON)
		}

	default:
		if flagTarget == "" {
			return fmt.Errorf("--target is required (or pipe targets to stdin, or use --targets-file)")
		}
		var nervaNoAuth bool
		if protocol == "" {
			// No --protocol specified — fingerprint with Nerva to auto-detect.
			fp, err := fingerprintSingleTarget(flagTarget, baseConfig)
			if err != nil {
				return err
			}
			protocol = fp.protocol
			nervaNoAuth = fp.noAuth

			// Apply subcommand protocol filter.
			if baseConfig.protocolFilter != nil && !baseConfig.protocolFilter(protocol) {
				return fmt.Errorf("discovered service %q on %s is not supported by 'brutus %s'",
					protocol, flagTarget, cmd.Name())
			}

			// Sync TLS state from fingerprint.
			if fp.tls {
				if baseConfig.web != nil {
					baseConfig.web.useHTTPS = true
				}
				if baseConfig.tlsMode == "disable" {
					baseConfig.tlsMode = "skip-verify"
				}
			}
		}
		allResults, hasSuccess = runSingleTargetMode(flagTarget, protocol, baseConfig, flagJSON, jsonWriter, nervaNoAuth)
	}

	// Final JSON output for multi-target modes
	if flagJSON && (useStdin || flagTargetsFile != "" || flagNmapFile != "" || flagMasscanFile != "") {
		outputJSONL(jsonWriter, allResults)
	}

	if !hasSuccess {
		return errNoSuccess
	}
	return nil
}

// runSingleTargetMode handles the single-target execution path.
// nervaNoAuth indicates Nerva live fingerprinting detected anonymous access.
func runSingleTargetMode(target, protocol string, baseConfig *runConfig, jsonOutput bool, jsonWriter io.Writer, nervaNoAuth bool) ([]brutus.Result, bool) {
	// AI mode for single target with HTTP protocol
	var aiCreds []brutus.Credential
	if baseConfig.aiMode && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = web.RouteHTTP(target, protocol, baseConfig.timeout, baseConfig.tlsMode, baseConfig.llmConfig)
	}

	// Print target info
	if !jsonOutput && !baseConfig.quiet {
		printTargetInfo(target, protocol, baseConfig, aiCreds)
	}

	var preResults []brutus.Result
	if nervaNoAuth {
		logVerbose(baseConfig.verbose, "Nerva detected unauthenticated access on %s (%s)", target, protocol)
		preResults = append(preResults, brutus.Result{
			Protocol: protocol,
			Target:   target,
			Username: "(unauthenticated)",
			Success:  true,
			Banner:   fmt.Sprintf("[CRITICAL] %s accessible without authentication (detected by Nerva fingerprinting)", protocol),
		})
	}

	results, success := runSingleTarget(target, protocol, baseConfig.tlsMode, baseConfig, aiCreds, nervaNoAuth)
	results = append(preResults, results...)
	if nervaNoAuth {
		success = true
	}

	// Output for single-target mode
	if jsonOutput {
		outputJSONL(jsonWriter, results)
	} else {
		outputHuman(results, baseConfig.useColor, baseConfig.quiet)
	}

	return results, success
}
