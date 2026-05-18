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
	flagProtocol    string
)

// Credential flags
var (
	flagUsernames       string
	flagUsernameFile    string
	flagPasswords       string
	flagPasswordFile    string
	flagKeyFile         string
	flagCredentials     string
	flagCredentialsFile string
)

// Performance flags
var (
	flagThreads     int
	flagTimeout     time.Duration
	flagRateLimit   float64
	flagJitter      time.Duration
	flagMaxAttempts int
	flagRetries     int
)

// Output flags
var (
	flagJSON       bool
	flagOutputFile string
	flagNoColor    bool
	flagQuiet      bool
	flagVerbose    bool
)

// TLS flags
var flagVerifyTLS bool

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

// Logon flags
var (
	flagExec string
	flagWeb  bool
	flagOpen bool
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
	pf.StringVar(&flagTargetsFile, "targets-file", "", "File of targets to test, one host:port per line (fingerprints with Nerva unless --protocol is set)")

	// Performance
	pf.IntVarP(&flagThreads, "threads", "t", 10, "Number of concurrent threads")
	pf.DurationVar(&flagTimeout, "timeout", 10*time.Second, "Per-target timeout")
	pf.Float64Var(&flagRateLimit, "rate-limit", 0, "Max requests per second (0 = unlimited)")
	pf.DurationVar(&flagJitter, "jitter", 0, "Random delay variance for rate limiting")
	pf.IntVar(&flagRetries, "retries", 2, "Max retries on connection error (0 = disabled)")

	// Output
	pf.BoolVar(&flagJSON, "json", false, "JSON output format")
	pf.StringVarP(&flagOutputFile, "output", "o", "", "Output file for JSON results (implies --json)")
	pf.BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "Quiet mode - only show successful credentials")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose mode - show detailed progress to stderr")
}

// registerCredentialFlags registers credential and brute-force strategy flags
// shared by the creds and web subcommands.
func registerCredentialFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagUsernames, "usernames", "u", "root,admin", "Comma-separated usernames")
	f.StringVarP(&flagUsernameFile, "username-file", "U", "", "Username file (one per line)")
	f.StringVarP(&flagPasswords, "passwords", "p", "", "Comma-separated passwords")
	f.StringVarP(&flagPasswordFile, "password-file", "P", "", "Password file (one per line)")
	f.StringVarP(&flagCredentials, "credentials", "c", "", "Comma-separated user:pass pairs (e.g., admin:admin,root:toor)")
	f.StringVarP(&flagCredentialsFile, "credentials-file", "C", "", "Credentials file (user:pass per line)")
	f.IntVar(&flagMaxAttempts, "max-attempts", 0, "Max password attempts per user (0 = unlimited)")
	f.BoolVar(&flagVerifyTLS, "verify", false, "Require strict TLS certificate verification")
}

// registerCredsFlags registers flags specific to the creds subcommand.
func registerCredsFlags(cmd *cobra.Command) {
	registerCredentialFlags(cmd)
	cmd.Flags().StringVarP(&flagKeyFile, "key", "k", "", "SSH private key file")
	cmd.Flags().StringVar(&flagProtocol, "protocol", "", "Protocol to use (auto-detected from nerva)")
}

// registerSNMPFlags registers flags specific to the snmp subcommand.
func registerSNMPFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&flagSNMPTier, "tier", "default", "Community string tier: default (~20), extended (~50), full (~120)")
	f.StringVarP(&flagPasswords, "passwords", "p", "", "Custom community strings (comma-separated)")
	f.StringVarP(&flagPasswordFile, "password-file", "P", "", "Community string file (one per line)")
}

// registerWebFlags registers flags specific to the web subcommand.
func registerWebFlags(cmd *cobra.Command) {
	registerCredentialFlags(cmd)
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
	cmd.Flags().StringVar(&flagExec, "exec", "", "Execute command via detected backdoor")
	cmd.Flags().BoolVar(&flagWeb, "web", false, "Start interactive web terminal via detected backdoor")
	cmd.Flags().BoolVar(&flagOpen, "open", false, "Auto-open browser when web terminal starts")
	cmd.Flags().BoolVar(&flagAIMode, "experimental-ai", false, "Enable Vision API for backdoor confirmation")
}

// registerRootFlags registers flags specific to the root command.
func registerRootFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&flagVersion, "version", false, "Show version information")
}

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

// buildBaseConfig constructs a baseConfigOptions with only the shared fields.
// Subcommand-specific loading (credentials, keys, AI config) is handled by
// each subcommand's runXxx function.
func buildBaseConfig(_ *cobra.Command) *baseConfigOptions {
	return &baseConfigOptions{
		threads:          flagThreads,
		timeout:          flagTimeout,
		useColor:         isColorEnabled(flagNoColor),
		quiet:            flagQuiet,
		verbose:          flagVerbose,
		protocolOverride: flagProtocol,
		aiMode:           flagAIMode,
		tlsMode:          determineTLSMode(flagVerifyTLS),
		rateLimit:        flagRateLimit,
		jitter:           flagJitter,
		maxAttempts:      flagMaxAttempts,
		maxRetries:       flagRetries,
		anthropicKey:     os.Getenv("ANTHROPIC_API_KEY"),
		perplexityKey:    os.Getenv("PERPLEXITY_API_KEY"),
	}
}

// loadCredentialInputs loads usernames, passwords, and pre-paired credentials
// from their respective flags. Called by creds and web subcommands.
func loadCredentialInputs(cmd *cobra.Command) (usernames, passwords []string, creds []brutus.Credential, err error) {
	passwordFlagSet := isFlagChanged(cmd, "passwords")
	usernameFlagSet := isFlagChanged(cmd, "usernames")

	usernames, err = loadUsernames(flagUsernames, flagUsernameFile, usernameFlagSet)
	if err != nil {
		return
	}
	if len(usernames) == 0 {
		usernames = []string{"root", "admin"}
	}

	passwords, err = loadPasswords(flagPasswords, flagPasswordFile, passwordFlagSet)
	if err != nil {
		return
	}

	creds, err = loadCredentials(flagCredentials, flagCredentialsFile)
	return
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
func shouldShowBanner(jsonOutput, stdinMode, quiet, useColor bool) bool {
	return !jsonOutput && !stdinMode && !quiet && useColor
}

// detectStdinMode returns true if stdin mode should be used.
// Stdin is auto-detected when no --target or --targets-file is provided
// and data is being piped in.
func detectStdinMode(target, targetsFile string) bool {
	if targetsFile != "" || target != "" {
		return false
	}
	return hasStdinData()
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
