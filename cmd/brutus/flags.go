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
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ---------------------------------------------------------------------------
// Package-level flag variables (bound to cobra/pflag)
// ---------------------------------------------------------------------------

// Target flags
var (
	flagTarget      string
	flagTargetsFile string
	flagFingerprint string
	flagNerva       bool
	flagProtocol    string
)

// Credential flags
var (
	flagUsernames    string
	flagUsernameFile string
	flagPasswords    string
	flagPasswordFile string
	flagKeyFile      string
)

// Performance flags
var (
	flagThreads       int
	flagTimeout       time.Duration
	flagStopOnSuccess bool
	flagRateLimit     float64
	flagJitter        time.Duration
	flagMaxAttempts   int
	flagSpray         bool
	flagRetries       int
)

// Output flags
var (
	flagJSON       bool
	flagOutputFile string
	flagBanner     bool
	flagNoColor    bool
	flagQuiet      bool
	flagVerbose    bool
)

// TLS flags
var flagVerifyTLS bool

// SSH/badkeys flags
var (
	flagNoBadkeys  bool
	flagBadkeysOnly bool
)

// SNMP flags
var flagSNMPTier string

// Browser/AI flags
var (
	flagBrowserTimeout time.Duration
	flagBrowserTabs    int
	flagBrowserVisible bool
	flagHTTPS          bool
	flagAIMode         bool
	flagAIVerify       bool
)

// Sticky keys flags
var (
	flagStickyKeys     bool
	flagStickyKeysExec string
	flagStickyKeysWeb  bool
	flagStickyKeysOpen bool
	flagNoUtilman      bool
)

// Fingerprint flags
var (
	flagFingerprintTimeout time.Duration
	flagFingerprintWorkers int
)

// Version flag
var flagVersion bool

// ---------------------------------------------------------------------------
// Flag registration functions
// ---------------------------------------------------------------------------

// registerSharedFlags registers persistent flags that propagate to all subcommands.
func registerSharedFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()

	// Target
	pf.StringVar(&flagTarget, "target", "", "Target host:port")
	pf.StringVar(&flagTargetsFile, "targets-file", "", "File of targets to test, one host:port per line (requires --protocol)")
	pf.StringVar(&flagFingerprint, "fingerprint", "", "File of host:port targets to fingerprint with Nerva before credential testing")
	pf.BoolVar(&flagNerva, "nerva", false, "Read targets from nerva JSON on stdin")

	// Credentials — short flags match the original CLI (-u, -U, -p, -P, -k)
	pf.StringVarP(&flagUsernames, "usernames", "u", "root,admin", "Comma-separated usernames")
	pf.StringVarP(&flagUsernameFile, "username-file", "U", "", "Username file (one per line)")
	pf.StringVarP(&flagPasswords, "passwords", "p", "", "Comma-separated passwords")
	pf.StringVarP(&flagPasswordFile, "password-file", "P", "", "Password file (one per line)")
	pf.StringVarP(&flagKeyFile, "key", "k", "", "SSH private key file")

	// Performance
	pf.IntVarP(&flagThreads, "threads", "t", 10, "Number of concurrent threads")
	pf.DurationVar(&flagTimeout, "timeout", 10*time.Second, "Per-credential timeout")
	pf.BoolVar(&flagStopOnSuccess, "stop-on-success", true, "Stop after first valid credential")
	pf.Float64Var(&flagRateLimit, "rate-limit", 0, "Max requests per second (0 = unlimited)")
	pf.DurationVar(&flagJitter, "jitter", 0, "Random delay variance for rate limiting")
	pf.IntVar(&flagMaxAttempts, "max-attempts", 0, "Max password attempts per user (0 = unlimited)")
	pf.BoolVar(&flagSpray, "spray", false, "Password spraying: try each password across all users")
	pf.IntVar(&flagRetries, "retries", 2, "Max retries per credential on connection error (0 = disabled)")

	// Output
	pf.BoolVar(&flagJSON, "json", false, "JSON output format")
	pf.StringVarP(&flagOutputFile, "output", "o", "", "Output file for JSON results (implies --json)")
	pf.BoolVar(&flagBanner, "banner", true, "Show ASCII banner")
	pf.BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "Quiet mode - only show successful credentials")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose mode - show detailed progress to stderr")

	// TLS
	pf.BoolVar(&flagVerifyTLS, "verify-tls", false, "Require strict TLS certificate verification")

	// Fingerprint
	pf.DurationVar(&flagFingerprintTimeout, "fingerprint-timeout", 5*time.Second, "Per-probe timeout for Nerva fingerprinting")
	pf.IntVar(&flagFingerprintWorkers, "fingerprint-workers", 50, "Concurrent workers for Nerva fingerprinting")

	// Version
	pf.BoolVar(&flagVersion, "version", false, "Show version information")
}

// registerCredsFlags registers flags specific to the creds subcommand.
func registerCredsFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagProtocol, "protocol", "", "Protocol to use (auto-detected from nerva)")
	cmd.Flags().StringVar(&flagSNMPTier, "snmp-tier", "default", "SNMP community string tier: default (20), extended (50), full (120)")
	cmd.Flags().BoolVar(&flagNoBadkeys, "no-badkeys", false, "Disable embedded bad key testing")
	cmd.Flags().BoolVar(&flagBadkeysOnly, "badkeys-only", false, "Only test embedded bad SSH keys (skip password wordlists)")
}

// registerWebFlags registers flags specific to the web subcommand.
func registerWebFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagProtocol, "protocol", "", "Protocol override (http or https)")
	cmd.Flags().DurationVar(&flagBrowserTimeout, "browser-timeout", 60*time.Second, "Total timeout for browser operations")
	cmd.Flags().IntVar(&flagBrowserTabs, "browser-tabs", 3, "Number of concurrent browser tabs")
	cmd.Flags().BoolVar(&flagBrowserVisible, "browser-visible", false, "Show browser window (demo mode)")
	cmd.Flags().BoolVar(&flagHTTPS, "https", false, "Use HTTPS for browser connections")
	cmd.Flags().BoolVar(&flagAIMode, "experimental-ai", false, "Enable AI-powered credential detection for HTTP services")
	cmd.Flags().BoolVar(&flagAIVerify, "experimental-ai-verify", false, "Use Claude Vision to verify login success")
}

// registerLogonFlags registers flags specific to the logon subcommand.
func registerLogonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagStickyKeysExec, "sticky-keys-exec", "", "Execute command via sticky keys backdoor")
	cmd.Flags().BoolVar(&flagStickyKeysWeb, "sticky-keys-web", false, "Start interactive web terminal via sticky keys backdoor")
	cmd.Flags().BoolVar(&flagStickyKeysOpen, "sticky-keys-open", false, "Auto-open browser when sticky keys web terminal starts")
	cmd.Flags().BoolVar(&flagNoUtilman, "no-utilman", false, "Disable utilman.exe backdoor detection")
	cmd.Flags().BoolVar(&flagAIMode, "experimental-ai", false, "Enable Vision API for backdoor confirmation")
}

// registerLegacyFlags registers all subcommand-specific flags on the root command
// so that the flat CLI (brutus --target ... --protocol ...) continues to work.
func registerLegacyFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	// From creds
	f.StringVar(&flagProtocol, "protocol", "", "Protocol to use (auto-detected from nerva)")
	f.StringVar(&flagSNMPTier, "snmp-tier", "default", "SNMP community string tier: default (20), extended (50), full (120)")
	f.BoolVar(&flagNoBadkeys, "no-badkeys", false, "Disable embedded bad key testing")
	f.BoolVar(&flagBadkeysOnly, "badkeys-only", false, "Only test embedded bad SSH keys")

	// From web
	f.DurationVar(&flagBrowserTimeout, "browser-timeout", 60*time.Second, "Total timeout for browser operations")
	f.IntVar(&flagBrowserTabs, "browser-tabs", 3, "Number of concurrent browser tabs")
	f.BoolVar(&flagBrowserVisible, "browser-visible", false, "Show browser window")
	f.BoolVar(&flagHTTPS, "https", false, "Use HTTPS for browser connections")
	f.BoolVar(&flagAIMode, "experimental-ai", false, "Enable AI-powered credential detection")
	f.BoolVar(&flagAIVerify, "experimental-ai-verify", false, "Use Claude Vision to verify login success")

	// From logon
	f.BoolVar(&flagStickyKeys, "sticky-keys", false, "Sticky keys backdoor detection mode for RDP")
	f.StringVar(&flagStickyKeysExec, "sticky-keys-exec", "", "Execute command via sticky keys backdoor")
	f.BoolVar(&flagStickyKeysWeb, "sticky-keys-web", false, "Start interactive web terminal via sticky keys backdoor")
	f.BoolVar(&flagStickyKeysOpen, "sticky-keys-open", false, "Auto-open browser for sticky keys web terminal")
	f.BoolVar(&flagNoUtilman, "no-utilman", false, "Disable utilman.exe backdoor detection")
}

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

// buildConfigFromFlags constructs a baseConfigOptions from the current flag state.
// The cobra.Command is needed to detect whether flags were explicitly set.
func buildConfigFromFlags(cmd *cobra.Command) (*baseConfigOptions, error) {
	// Detect whether credential flags were explicitly set
	passwordFlagSet := isFlagChanged(cmd, "passwords")
	passwordFileFlagSet := isFlagChanged(cmd, "password-file")
	usernameFlagSet := isFlagChanged(cmd, "usernames")
	usernameFileFlagSet := isFlagChanged(cmd, "username-file")

	useColor := isColorEnabled(flagNoColor)

	// Read API keys
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")
	perplexityKey := os.Getenv("PERPLEXITY_API_KEY")

	aiLLMConfig, err := setupAIConfig(flagAIMode, anthropicKey, perplexityKey)
	if err != nil {
		return nil, err
	}

	if flagAIVerify && anthropicKey == "" {
		return nil, fmt.Errorf("--experimental-ai-verify requires ANTHROPIC_API_KEY environment variable")
	}

	// Validate key file flags
	if err := validateKeyFileFlags(flagKeyFile, usernameFlagSet, flagUsernameFile); err != nil {
		return nil, err
	}

	// Validate fingerprint + credential combinations
	if flagFingerprint != "" {
		hasExplicitUsers := usernameFlagSet || usernameFileFlagSet
		hasExplicitPasswords := passwordFlagSet || passwordFileFlagSet
		if hasExplicitPasswords && !hasExplicitUsers {
			return nil, fmt.Errorf("--fingerprint with -p/-P also requires -u or -U to specify usernames\nExample: brutus --fingerprint targets.txt -u admin -P passwords.txt")
		}
		if hasExplicitUsers && !hasExplicitPasswords {
			return nil, fmt.Errorf("--fingerprint with -u/-U also requires -p or -P to specify passwords\nExample: brutus --fingerprint targets.txt -u admin -P passwords.txt")
		}
	}

	// Load credentials
	usernameList, err := loadUsernames(flagUsernames, flagUsernameFile, usernameFlagSet)
	if err != nil {
		return nil, err
	}
	if len(usernameList) == 0 {
		usernameList = []string{"root", "admin"}
	}

	passwordList, err := loadPasswords(flagPasswords, flagPasswordFile, passwordFlagSet)
	if err != nil {
		return nil, err
	}

	keyList, err := loadKey(flagKeyFile)
	if err != nil {
		return nil, err
	}

	return &baseConfigOptions{
		usernames:          usernameList,
		passwords:          passwordList,
		keys:               keyList,
		threads:            flagThreads,
		timeout:            flagTimeout,
		stopOnSuccess:      flagStopOnSuccess,
		snmpTier:           flagSNMPTier,
		llmConfig:          aiLLMConfig,
		browserTimeout:     flagBrowserTimeout,
		browserTabs:        flagBrowserTabs,
		browserVisible:     flagBrowserVisible,
		useHTTPS:           flagHTTPS,
		useColor:           useColor,
		quiet:              flagQuiet,
		verbose:            flagVerbose,
		useBadkeys:         !flagNoBadkeys,
		badkeysOnly:        flagBadkeysOnly,
		protocolOverride:   flagProtocol,
		aiMode:             flagAIMode,
		tlsMode:            determineTLSMode(flagVerifyTLS),
		rateLimit:          flagRateLimit,
		jitter:             flagJitter,
		maxAttempts:        flagMaxAttempts,
		sprayMode:          flagSpray,
		maxRetries:         flagRetries,
		anthropicKey:       anthropicKey,
		perplexityKey:      perplexityKey,
		stickyKeys:         flagStickyKeys,
		stickyKeysExec:     flagStickyKeysExec,
		stickyKeysWeb:      flagStickyKeysWeb,
		stickyKeysOpen:     flagStickyKeysOpen,
		aiVerify:           flagAIVerify,
		noUtilman:          flagNoUtilman,
		fingerprintTimeout: flagFingerprintTimeout,
		fingerprintWorkers: flagFingerprintWorkers,
	}, nil
}

// isFlagChanged returns true if the named flag was explicitly set on cmd or its parents.
func isFlagChanged(cmd *cobra.Command, name string) bool {
	f := cmd.Flags().Lookup(name)
	if f != nil && f.Changed {
		return true
	}
	// Also check persistent flags (inherited from parent)
	pf := cmd.InheritedFlags().Lookup(name)
	return pf != nil && pf.Changed
}

// ---------------------------------------------------------------------------
// Utility functions (moved from main.go)
// ---------------------------------------------------------------------------

// setupAIConfig creates the LLM configuration for AI mode.
func setupAIConfig(aiMode bool, anthropicKey, perplexityKey string) (*brutus.LLMConfig, error) {
	if !aiMode {
		return nil, nil
	}
	if anthropicKey == "" {
		return nil, fmt.Errorf("--experimental-ai requires ANTHROPIC_API_KEY for Claude Vision (screenshot analysis)\n       PERPLEXITY_API_KEY is optional for additional web search")
	}
	if perplexityKey != "" {
		return &brutus.LLMConfig{Enabled: true, Provider: "perplexity", APIKey: perplexityKey}, nil
	}
	return &brutus.LLMConfig{Enabled: true, Provider: "claude-vision", APIKey: anthropicKey}, nil
}

// setupOutputWriter configures the JSON output writer and returns a cleanup function.
func setupOutputWriter(outputFile string) (w io.Writer, forceJSON bool, cleanup func(), err error) {
	if outputFile == "" {
		return os.Stdout, false, func() {}, nil
	}
	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, false, func() {}, fmt.Errorf("creating output file: %w", err)
	}
	return f, true, func() { _ = f.Close() }, nil
}

// shouldShowBanner determines whether to display the ASCII art banner.
func shouldShowBanner(showBanner, jsonOutput, stdinMode, quiet, useColor bool) bool {
	return showBanner && !jsonOutput && !stdinMode && !quiet && useColor
}

// detectStdinMode returns true if stdin mode should be used.
func detectStdinMode(stdinFlag bool, target, fingerprintFile string) bool {
	if fingerprintFile != "" {
		return stdinFlag
	}
	return stdinFlag || (target == "" && hasStdinData())
}

// isColorEnabled returns true if colored output should be used.
func isColorEnabled(noColor bool) bool {
	return !noColor && isTerminal()
}

// validateKeyFileFlags checks that -k is used with explicit -u or -U.
func validateKeyFileFlags(keyFile string, usernameFlagSet bool, usernameFile string) error {
	if keyFile != "" && !usernameFlagSet && usernameFile == "" {
		return fmt.Errorf("-k requires -u or -U to specify which username(s) to test with the key\nExample: brutus --target host:22 --protocol ssh -u vagrant -k mykey.pem")
	}
	return nil
}

// validateTargetFlags checks that required flags are provided for single-target mode.
func validateTargetFlags(target, protocol string) error {
	if target == "" {
		return fmt.Errorf("--target is required (or pipe nerva JSON to stdin)")
	}
	if protocol == "" {
		return fmt.Errorf("--protocol is required when using --target\nExample: brutus --target %s --protocol ssh", target)
	}
	return nil
}

// hasStdinData checks if stdin has data available (i.e., is being piped to).
func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// isTerminal checks if stdout is a terminal.
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
