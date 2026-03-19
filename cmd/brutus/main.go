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
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"

	// Import plugins and analyzers to register them
	_ "github.com/praetorian-inc/brutus/internal/analyzers"
	_ "github.com/praetorian-inc/brutus/internal/plugins"
)

// Version info - set by ldflags during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

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
	return f, true, func() { f.Close() }, nil
}

// shouldShowBanner determines whether to display the ASCII art banner.
func shouldShowBanner(showBanner, jsonOutput, stdinMode, quiet, useColor bool) bool {
	return showBanner && !jsonOutput && !stdinMode && !quiet && useColor
}

// detectStdinMode returns true if stdin mode should be used (explicit flag or piped data without target).
func detectStdinMode(stdinFlag bool, target string) bool {
	return stdinFlag || (target == "" && hasStdinData())
}

// isColorEnabled returns true if colored output should be used.
func isColorEnabled(noColor bool) bool {
	return !noColor && isTerminal()
}

func main() {
	// Command-line flags
	target := flag.String("target", "", "Target host:port")
	showVersion := flag.Bool("version", false, "Show version information")
	protocol := flag.String("protocol", "", "Protocol to use (auto-detected from nerva)")
	usernames := flag.String("u", "root,admin", "Comma-separated usernames")
	usernameFile := flag.String("U", "", "Username file (one per line)")
	passwords := flag.String("p", "", "Comma-separated passwords")
	passwordFile := flag.String("P", "", "Password file (one per line)")
	keyFile := flag.String("k", "", "SSH private key file")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-credential timeout")
	jsonOutput := flag.Bool("json", false, "JSON output format")
	outputFile := flag.String("o", "", "Output file for JSON results (default: stdout)")
	stopOnSuccess := flag.Bool("stop-on-success", true, "Stop after first valid credential")
	snmpTier := flag.String("snmp-tier", "default", "SNMP community string tier: default (20), extended (50), full (120)")
	rateLimit := flag.Float64("rate-limit", 0, "Max requests per second (0 = unlimited)")
	jitter := flag.Duration("jitter", 0, "Random delay variance for rate limiting (e.g., 100ms)")
	stdinMode := flag.Bool("nerva", false, "Read targets from nerva JSON on stdin")
	maxAttempts := flag.Int("max-attempts", 0, "Max password attempts per user (0 = unlimited)")
	sprayMode := flag.Bool("spray", false, "Password spraying: try each password across all users")
	retries := flag.Int("retries", 2, "Max retries per credential on connection error (0 = no retry)")
	showBanner := flag.Bool("banner", true, "Show ASCII banner")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("q", false, "Quiet mode - only show successful credentials")
	verbose := flag.Bool("v", false, "Verbose mode - show detailed progress to stderr")
	noBadkeys := flag.Bool("no-badkeys", false, "Disable embedded bad key testing")
	badkeysOnly := flag.Bool("badkeys-only", false, "Only test embedded bad SSH keys (skip password wordlists and non-SSH protocols)")
	verifyTLS := flag.Bool("verify-tls", false, "Require strict TLS certificate verification (default: disabled)")

	// Custom usage
	flag.Usage = customUsage

	// Browser plugin flags
	browserTimeout := flag.Duration("browser-timeout", 60*time.Second, "Total timeout for browser operations")
	browserTabs := flag.Int("browser-tabs", 3, "Number of concurrent browser tabs")
	browserVisible := flag.Bool("browser-visible", false, "Show browser window (demo mode)")
	useHTTPS := flag.Bool("https", false, "Use HTTPS for browser connections")
	aiMode := flag.Bool("experimental-ai", false, "Enable AI-powered credential detection for HTTP services (experimental)")
	stickyKeys := flag.Bool("sticky-keys", false, "Enable sticky keys backdoor detection for RDP targets")
	stickyKeysExec := flag.String("sticky-keys-exec", "", "Execute command via sticky keys backdoor (requires --sticky-keys)")
	stickyKeysWeb := flag.Bool("sticky-keys-web", false, "Start interactive web terminal via sticky keys backdoor (requires --sticky-keys)")
	stickyKeysOpen := flag.Bool("sticky-keys-open", false, "Auto-open browser when sticky keys web terminal starts")
	nlaCheck := flag.Bool("nla-check", false, "NLA fingerprint scan: check if RDP targets require NLA (no auth, fast)")
	stickyKeysScan := flag.Bool("sticky-keys-scan", false, "Sticky keys scan-only mode: detect backdoor without brute force")

	flag.Parse()

	// Track whether -p and -u flags were explicitly set
	passwordFlagSet := false
	usernameFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			passwordFlagSet = true
		}
		if f.Name == "u" {
			usernameFlagSet = true
		}
	})

	// Detect terminal and configure colors
	useColor := isColorEnabled(*noColor)

	// Show version and exit
	if *showVersion {
		printVersion(useColor)
		os.Exit(0)
	}

	// Auto-detect nerva mode: if stdin has data and no target specified, use nerva mode
	useStdin := detectStdinMode(*stdinMode, *target)

	// Show banner (unless in JSON mode, nerva mode, or quiet mode)
	if shouldShowBanner(*showBanner, *jsonOutput, useStdin, *quiet, useColor) {
		printBanner(useColor)
	}

	// Read API keys once (used by AI mode and browser research)
	perplexityKey := os.Getenv("PERPLEXITY_API_KEY")
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

	aiLLMConfig, err := setupAIConfig(*aiMode, anthropicKey, perplexityKey)
	if err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}

	// Determine if badkeys should be used (enabled by default, --no-badkeys disables)
	useBadkeys := !*noBadkeys

	// Validate: -k requires explicit -u or -U (not default usernames)
	if err := validateKeyFileFlags(*keyFile, usernameFlagSet, *usernameFile); err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(*outputFile)
	if err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}
	if forceJSON {
		*jsonOutput = true
	}

	usernameList, err := loadUsernames(*usernames, *usernameFile, usernameFlagSet)
	if err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}
	// Fallback: if neither -u nor -U was provided, use default usernames
	if len(usernameList) == 0 {
		usernameList = []string{"root", "admin"}
	}
	passwordList, err := loadPasswords(*passwords, *passwordFile, passwordFlagSet)
	if err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}
	keyList, err := loadKey(*keyFile)
	if err != nil {
		errMsg(useColor, "%v", err)
		os.Exit(1)
	}

	// Prepare common config options
	baseConfig := baseConfigOptions{
		usernames:        usernameList,
		passwords:        passwordList,
		keys:             keyList,
		threads:          *threads,
		timeout:          *timeout,
		stopOnSuccess:    *stopOnSuccess,
		snmpTier:         *snmpTier,
		llmConfig:        aiLLMConfig,
		browserTimeout:   *browserTimeout,
		browserTabs:      *browserTabs,
		browserVisible:   *browserVisible,
		useHTTPS:         *useHTTPS,
		useColor:         useColor,
		quiet:            *quiet,
		verbose:          *verbose,
		useBadkeys:       useBadkeys,
		badkeysOnly:      *badkeysOnly,
		protocolOverride: *protocol,
		aiMode:           *aiMode,
		tlsMode:          determineTLSMode(*verifyTLS),
		rateLimit:        *rateLimit,
		jitter:           *jitter,
		maxAttempts:      *maxAttempts,
		sprayMode:        *sprayMode,
		maxRetries:       *retries,
		anthropicKey:     anthropicKey,
		perplexityKey:    perplexityKey,
		stickyKeys:       *stickyKeys,
		stickyKeysExec:   *stickyKeysExec,
		stickyKeysWeb:    *stickyKeysWeb,
		stickyKeysOpen:   *stickyKeysOpen,
		nlaCheck:         *nlaCheck,
		stickyKeysScan:   *stickyKeysScan,
	}

	var allResults []brutus.Result
	var hasSuccess bool


	// Scan-only modes: bypass normal brute force entirely
	if baseConfig.nlaCheck || baseConfig.stickyKeysScan {
		var scanResults []brutus.Result
		if useStdin {
			scanResults, hasSuccess = runScanFromStdin(&baseConfig)
		} else {
			if *target == "" {
				errMsg(useColor, "--target is required for scan modes (or pipe nerva JSON to stdin)")
				closeOutput()
				os.Exit(1)
			}
			scanResults, hasSuccess = runScanSingleTarget(*target, &baseConfig)
		}
		if *jsonOutput {
			outputScanJSONL(jsonWriter, scanResults)
		} else {
			outputScanHuman(scanResults, useColor)
		}
		closeOutput()
		if !hasSuccess {
			os.Exit(1)
		}
		return
	}

	if useStdin {
		allResults, hasSuccess = runFromStdin(&baseConfig, *jsonOutput)
	} else {
		if err := validateTargetFlags(*target, *protocol); err != nil {
			errMsg(useColor, "%v", err)
			flag.Usage()
			closeOutput()
			os.Exit(1)
		}
		allResults, hasSuccess = runSingleTargetMode(*target, *protocol, &baseConfig, *jsonOutput, jsonWriter)
	}

	// Final JSON output for nerva mode
	if *jsonOutput && useStdin {
		outputJSONL(jsonWriter, allResults)
	}

	// Close output file and exit with appropriate code
	closeOutput()
	if !hasSuccess {
		os.Exit(1)
	}
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

// hasStdinData checks if stdin has data available (i.e., is being piped to)
func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	// Check if stdin is a pipe or has data
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
