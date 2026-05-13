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
	"os"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var rootCmd = &cobra.Command{
	Use:   "brutus",
	Short: "Brutus - Et tu, Brute?",
	Long: `Brutus - Et tu, Brute?
Modern credential auditing tool for network services, web panels, and Windows logon screens.

Subcommands:
  creds    Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)
  web      Audit HTTP/web panel credentials (Basic Auth, form login, AI-powered)
  logon    Detect Windows logon-screen backdoors (sticky keys, utilman)

Legacy usage (backward compatible):
  brutus --target <host:port> --protocol <proto> [options]
  brutus --fingerprint <targets.txt> [options]
  naabu ... | nerva --json | brutus [options]`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runLegacy,
}

func init() {
	registerSharedFlags(rootCmd)
	registerLegacyFlags(rootCmd)

	rootCmd.AddCommand(credsCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(logonCmd)
}

// runLegacy handles the flat CLI for backward compatibility:
//
//	brutus --target host:22 --protocol ssh -u root -p password
//	brutus --fingerprint targets.txt -u admin -P passwords.txt
//	nerva --json | brutus --json
func runLegacy(cmd *cobra.Command, args []string) error {
	// Show version and exit
	if flagVersion {
		useColor := isColorEnabled(flagNoColor)
		printVersion(useColor)
		return nil
	}

	baseConfig, err := buildConfigFromFlags(cmd)
	if err != nil {
		return err
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

	var allResults []brutus.Result
	var hasSuccess bool

	// Scan/detection mode: --sticky-keys bypasses normal brute force
	stickyKeysDetect := baseConfig.stickyKeys && baseConfig.stickyKeysExec == "" && !baseConfig.stickyKeysWeb
	if stickyKeysDetect {
		var scanResults []brutus.Result
		if useStdin {
			scanResults, hasSuccess = runScanFromStdin(baseConfig)
		} else {
			if flagTarget == "" {
				return fmt.Errorf("--target is required for scan modes (or pipe nerva JSON to stdin)")
			}
			scanResults, hasSuccess = runScanSingleTarget(flagTarget, baseConfig)
		}
		if flagJSON {
			outputScanJSONL(jsonWriter, scanResults)
		} else {
			outputScanHuman(scanResults, baseConfig.useColor)
		}
		if !hasSuccess {
			os.Exit(1)
		}
		return nil
	}

	switch {
	case useStdin:
		if flagTargetsFile != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with --nerva / piped stdin")
		}
		if flagFingerprint != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --nerva / piped stdin")
		}
		allResults, hasSuccess = runFromStdin(baseConfig, flagJSON)

	case flagFingerprint != "":
		if flagTarget != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --target")
		}
		if flagTargetsFile != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --targets-file")
		}
		targetsList, err := brutus.LoadTargetsFromFile(flagFingerprint)
		if err != nil {
			return err
		}
		if len(targetsList) == 0 {
			return fmt.Errorf("fingerprint file %q has no targets after stripping comments and blank lines", flagFingerprint)
		}
		allResults, hasSuccess = runFromFingerprint(targetsList, baseConfig, flagJSON)

	case flagTargetsFile != "":
		if flagTarget != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with --target")
		}
		if flagProtocol == "" {
			return fmt.Errorf("--targets-file requires --protocol (no nerva fingerprinting in this mode)")
		}
		targetsList, err := brutus.LoadTargetsFromFile(flagTargetsFile)
		if err != nil {
			return err
		}
		if len(targetsList) == 0 {
			return fmt.Errorf("targets file %q has no targets after stripping comments and blank lines", flagTargetsFile)
		}
		allResults, hasSuccess = runFromTargetsFile(targetsList, baseConfig, flagJSON)

	default:
		if err := validateTargetFlags(flagTarget, flagProtocol); err != nil {
			return err
		}
		allResults, hasSuccess = runSingleTargetMode(flagTarget, flagProtocol, baseConfig, flagJSON, jsonWriter)
	}

	// Final JSON output for multi-target modes
	if flagJSON && (useStdin || flagTargetsFile != "" || flagFingerprint != "") {
		outputJSONL(jsonWriter, allResults)
	}

	if !hasSuccess {
		os.Exit(1)
	}
	return nil
}

// runSubcommand is the shared execution path for creds, web, and logon subcommands.
// It handles mode dispatch (single target, targets-file, fingerprint, stdin) with
// the protocol filtering and overrides already applied to baseConfig by the caller.
func runSubcommand(cmd *cobra.Command, baseConfig *baseConfigOptions) error {
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

	var allResults []brutus.Result
	var hasSuccess bool

	protocol := baseConfig.protocolOverride

	switch {
	case useStdin:
		if flagTargetsFile != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with --nerva / piped stdin")
		}
		if flagFingerprint != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --nerva / piped stdin")
		}
		allResults, hasSuccess = runFromStdin(baseConfig, flagJSON)

	case flagFingerprint != "":
		if flagTarget != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --target")
		}
		if flagTargetsFile != "" {
			return fmt.Errorf("--fingerprint is mutually exclusive with --targets-file")
		}
		targetsList, err := brutus.LoadTargetsFromFile(flagFingerprint)
		if err != nil {
			return err
		}
		if len(targetsList) == 0 {
			return fmt.Errorf("fingerprint file %q has no targets after stripping comments and blank lines", flagFingerprint)
		}
		allResults, hasSuccess = runFromFingerprint(targetsList, baseConfig, flagJSON)

	case flagTargetsFile != "":
		if flagTarget != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with --target")
		}
		if protocol == "" {
			return fmt.Errorf("--targets-file requires --protocol")
		}
		targetsList, err := brutus.LoadTargetsFromFile(flagTargetsFile)
		if err != nil {
			return err
		}
		if len(targetsList) == 0 {
			return fmt.Errorf("targets file %q has no targets after stripping comments and blank lines", flagTargetsFile)
		}
		allResults, hasSuccess = runFromTargetsFile(targetsList, baseConfig, flagJSON)

	default:
		if flagTarget == "" {
			return fmt.Errorf("--target is required (or pipe nerva JSON to stdin, or use --fingerprint)")
		}
		if protocol == "" {
			return fmt.Errorf("--protocol is required when using --target\nExample: brutus %s --target %s --protocol ssh", cmd.Name(), flagTarget)
		}
		allResults, hasSuccess = runSingleTargetMode(flagTarget, protocol, baseConfig, flagJSON, jsonWriter)
	}

	// Final JSON output for multi-target modes
	if flagJSON && (useStdin || flagTargetsFile != "" || flagFingerprint != "") {
		outputJSONL(jsonWriter, allResults)
	}

	if !hasSuccess {
		os.Exit(1)
	}
	return nil
}

// runSingleTargetMode handles the single-target execution path.
func runSingleTargetMode(target, protocol string, baseConfig *baseConfigOptions, jsonOutput bool, jsonWriter io.Writer) ([]brutus.Result, bool) {
	// AI mode for single target with HTTP protocol
	var aiCreds []brutus.Credential
	if baseConfig.aiMode && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = routeHTTPWithAI(target, protocol, baseConfig)
	}

	// Print target info
	if !jsonOutput && !baseConfig.quiet {
		printTargetInfo(target, protocol, baseConfig, aiCreds)
	}

	results, success := runSingleTarget(target, protocol, baseConfig.tlsMode, baseConfig, aiCreds)

	// Output for single-target mode
	if jsonOutput {
		outputJSONL(jsonWriter, results)
	} else {
		outputHuman(results, baseConfig.useColor, baseConfig.quiet)
	}

	return results, success
}
