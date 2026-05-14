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
var errNoSubcommand = fmt.Errorf("a subcommand is required (creds, web, badkeys, logon)")

var rootCmd = &cobra.Command{
	Use:   "brutus",
	Short: "Brutus - Et tu, Brute?",
	Long: `Brutus - Et tu, Brute?
Modern credential auditing tool for network services, web panels, and Windows logon screens.

Subcommands:
  creds    Test default credentials on non-HTTP services (SSH, databases, SMB, etc.)
  web      Audit HTTP/web panel credentials (Basic Auth, form login, AI-powered)
  badkeys  Test known weak/compromised SSH keys against targets
  logon    Detect Windows logon-screen backdoors (sticky keys, utilman)

All subcommands accept targets via stdin (one per line, formats can be mixed):
  Nerva JSON:  {"ip":"10.0.0.1","port":22,"protocol":"ssh"}
  URI scheme:  ssh://192.168.1.1:22, rdp://10.0.0.50:3389
  Bare target: 192.168.1.1:22 (auto-fingerprinted with Nerva)`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runRoot,
}

func init() {
	registerSharedFlags(rootCmd)
	registerRootFlags(rootCmd)

	rootCmd.AddCommand(credsCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(badkeysCmd)
	rootCmd.AddCommand(logonCmd)
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
func runSubcommand(cmd *cobra.Command, baseConfig *baseConfigOptions) error {
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
	if shouldShowBanner(flagJSON, useStdin, flagQuiet, baseConfig.useColor) {
		printBanner(baseConfig.useColor)
	}

	var allResults []brutus.Result
	var hasSuccess bool

	protocol := baseConfig.protocolOverride

	switch {
	case useStdin:
		if flagTargetsFile != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with piped stdin")
		}
		allResults, hasSuccess = runFromStdin(baseConfig, flagJSON)

	case flagTargetsFile != "":
		if flagTarget != "" {
			return fmt.Errorf("--targets-file is mutually exclusive with --target")
		}
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
		if protocol == "" {
			return fmt.Errorf("--protocol is required when using --target\nExample: brutus %s --target %s --protocol ssh", cmd.Name(), flagTarget)
		}
		allResults, hasSuccess = runSingleTargetMode(flagTarget, protocol, baseConfig, flagJSON, jsonWriter)
	}

	// Final JSON output for multi-target modes
	if flagJSON && (useStdin || flagTargetsFile != "") {
		outputJSONL(jsonWriter, allResults)
	}

	if !hasSuccess {
		return errNoSuccess
	}
	return nil
}

// runSingleTargetMode handles the single-target execution path.
func runSingleTargetMode(target, protocol string, baseConfig *baseConfigOptions, jsonOutput bool, jsonWriter io.Writer) ([]brutus.Result, bool) {
	// AI mode for single target with HTTP protocol
	var aiCreds []brutus.Credential
	if baseConfig.aiMode && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = web.RouteHTTP(target, protocol, baseConfig.timeout, baseConfig.tlsMode, baseConfig.llmConfig)
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
