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
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"

	// Import plugins and analyzers to register them
	_ "github.com/praetorian-inc/brutus/internal/analyzers"
	"github.com/praetorian-inc/brutus/internal/analyzers/vision"
	_ "github.com/praetorian-inc/brutus/internal/plugins"
	"github.com/praetorian-inc/brutus/internal/plugins/browser"
	"github.com/praetorian-inc/brutus/internal/plugins/snmp"

	"context"
)

// ANSI Color Constants
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorDim    = "\033[2m"
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
)

// Output symbols (ASCII for compatibility)
const (
	SymbolSuccess = "[+]"
	SymbolError   = "[-]"
	SymbolWarning = "[!]"
	SymbolInfo    = "[*]"
	SymbolLLM     = "[AI]"
)

// ASCII Banner
const banner = `
    ____  ____  __  ____________  _______
   / __ )/ __ \/ / / /_  __/ / / / ___/
  / __  / /_/ / / / / / / / / / /\__ \
 / /_/ / _, _/ /_/ / / / / /_/ /___/ /
/_____/_/ |_|\____/ /_/  \____//____/

 Et tu, Brute?
 Praetorian Security, Inc.
`

// Version info - set by ldflags during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// FingerprintxResult represents the JSON output from fingerprintx
type FingerprintxResult struct {
	IP        string                 `json:"ip"`
	Port      int                    `json:"port"`
	Protocol  string                 `json:"protocol"`
	Transport string                 `json:"transport"`
	Metadata  map[string]interface{} `json:"metadata"`
}

func main() {
	// Command-line flags
	target := flag.String("target", "", "Target host:port")
	showVersion := flag.Bool("version", false, "Show version information")
	protocol := flag.String("protocol", "", "Protocol to use (auto-detected from fingerprintx)")
	usernames := flag.String("u", "root,admin", "Comma-separated usernames")
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
	stdinMode := flag.Bool("stdin", false, "Read targets from stdin (fingerprintx JSON format)")
	maxAttempts := flag.Int("max-attempts", 0, "Max password attempts per user (0 = unlimited)")
	sprayMode := flag.Bool("spray", false, "Password spraying: try each password across all users")
	showBanner := flag.Bool("banner", true, "Show ASCII banner")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("q", false, "Quiet mode - only show successful credentials")
	verbose := flag.Bool("v", false, "Verbose mode - show detailed progress to stderr")
	badkeys := flag.Bool("badkeys", true, "Test embedded bad SSH keys (rapid7/ssh-badkeys, vagrant)")
	noBadkeys := flag.Bool("no-badkeys", false, "Disable embedded bad key testing")
	verifyTLS := flag.Bool("verify-tls", false, "Require strict TLS certificate verification (default: disabled)")

	// Custom usage
	flag.Usage = customUsage

	// Browser plugin flags
	browserTimeout := flag.Duration("browser-timeout", 60*time.Second, "Total timeout for browser operations")
	browserTabs := flag.Int("browser-tabs", 3, "Number of concurrent browser tabs")
	browserVisible := flag.Bool("browser-visible", false, "Show browser window (demo mode)")
	useHTTPS := flag.Bool("https", false, "Use HTTPS for browser connections")
	aiMode := flag.Bool("experimental-ai", false, "Enable AI-powered credential detection for HTTP services (experimental)")
	aiVerify := flag.Bool("experimental-ai-verify", false, "Use Claude Vision to verify login success (more accurate but slower)")

	flag.Parse()

	// Track whether -p flag was explicitly set (to support empty passwords)
	passwordFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			passwordFlagSet = true
		}
	})

	// Detect terminal and configure colors
	useColor := !*noColor && isTerminal()

	// Show version and exit
	if *showVersion {
		printVersion(useColor)
		os.Exit(0)
	}

	// Auto-detect stdin mode: if stdin has data and no target specified, use stdin mode
	useStdin := *stdinMode || (*target == "" && hasStdinData())

	// Show banner (unless in JSON mode, stdin mode, or quiet mode)
	if *showBanner && !*jsonOutput && !useStdin && !*quiet && useColor {
		printBanner(useColor)
	}

	// AI mode validation - requires ANTHROPIC_API_KEY for Claude Vision
	// PERPLEXITY_API_KEY is optional for additional web search credential research
	var aiLLMConfig *brutus.LLMConfig
	if *aiMode {
		perplexityKey := os.Getenv("PERPLEXITY_API_KEY")
		anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

		if anthropicKey == "" {
			fmt.Fprintf(os.Stderr, "Error: --experimental-ai requires ANTHROPIC_API_KEY for Claude Vision (screenshot analysis)\n")
			fmt.Fprintf(os.Stderr, "       PERPLEXITY_API_KEY is optional for additional web search\n")
			os.Exit(1)
		}

		// Create LLM config - use Perplexity if available, otherwise just enable AI mode
		if perplexityKey != "" {
			aiLLMConfig = &brutus.LLMConfig{
				Enabled:  true,
				Provider: "perplexity",
				APIKey:   perplexityKey,
			}
		} else {
			// AI mode enabled but no Perplexity - Claude Vision will suggest credentials
			aiLLMConfig = &brutus.LLMConfig{
				Enabled:  true,
				Provider: "claude-vision",
				APIKey:   anthropicKey,
			}
		}
	}

	// Determine if badkeys should be used (--no-badkeys overrides --badkeys)
	useBadkeys := *badkeys && !*noBadkeys

	// Validate: -k requires explicit -u (not default usernames)
	if *keyFile != "" && *usernames == "root,admin" {
		fmt.Fprintf(os.Stderr, "Error: -k requires -u to specify which username(s) to test with the key\n")
		fmt.Fprintf(os.Stderr, "Example: brutus --target host:22 --protocol ssh -u vagrant -k mykey.pem\n")
		os.Exit(1)
	}

	// Setup JSON output writer (file or stdout)
	var jsonWriter io.Writer = os.Stdout
	var outputFileHandle *os.File
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		outputFileHandle = f
		jsonWriter = f
		// If -o is specified, imply --json
		*jsonOutput = true
	}
	// Helper to close output file if opened
	closeOutput := func() {
		if outputFileHandle != nil {
			outputFileHandle.Close()
		}
	}

	// Prepare common config options
	baseConfig := baseConfigOptions{
		usernames:        strings.Split(*usernames, ","),
		passwords:        loadPasswords(*passwords, *passwordFile, passwordFlagSet),
		keys:             loadKey(*keyFile),
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
		protocolOverride: *protocol,
		aiMode:           *aiMode,
		aiVerify:         *aiVerify,
		tlsMode:          determineTLSMode(*verifyTLS),
		rateLimit:        *rateLimit,
		jitter:           *jitter,
		maxAttempts:      *maxAttempts,
		sprayMode:        *sprayMode,
	}

	var allResults []brutus.Result
	var hasSuccess bool

	if useStdin {
		// Read targets from stdin (fingerprintx JSON)
		allResults, hasSuccess = runFromStdin(&baseConfig, *jsonOutput)
	} else {
		// Single target mode
		if *target == "" {
			if useColor {
				fmt.Fprintf(os.Stderr, "%s%sError:%s --target is required (or pipe data to stdin)\n\n%s", ColorBold, ColorRed, ColorReset, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: --target is required (or pipe data to stdin)\n\n")
			}
			flag.Usage()
			closeOutput()
			os.Exit(1)
		}

		// Require protocol for single target mode
		proto := *protocol
		if proto == "" {
			if baseConfig.useColor {
				fmt.Fprintf(os.Stderr, "%s%sError:%s --protocol is required when using --target\n", ColorBold, ColorRed, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: --protocol is required when using --target\n")
			}
			fmt.Fprintf(os.Stderr, "Example: brutus --target %s --protocol ssh\n", *target)
			closeOutput()
			os.Exit(1)
		}

		// AI mode for single target with HTTP protocol
		if baseConfig.aiMode && (proto == "http" || proto == "https") {
			useHTTPS := proto == "https"
			authType, banner := detectHTTPAuthTypeWithBanner(*target, useHTTPS, baseConfig.timeout, baseConfig.verbose)
			if authType == "basic" {
				if baseConfig.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s uses Basic Auth, using LLM analysis\n", *target)
				}
				if baseConfig.llmConfig != nil && baseConfig.llmConfig.Enabled {
					creds := researchCredentialsWithLLM(*target, banner, baseConfig.llmConfig, baseConfig.verbose)
					if len(creds) > 0 {
						baseConfig.aiResearchedCreds = creds
						if baseConfig.verbose {
							fmt.Fprintf(os.Stderr, "[verbose] LLM researched %d credential pairs for %s\n", len(creds), *target)
						}
					}
				}
			} else {
				proto = "browser"
				if baseConfig.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s appears form-based, using browser automation\n", *target)
				}
			}
		}

		// Print target info
		if !*jsonOutput && !*quiet {
			printTargetInfo(*target, proto, &baseConfig)
		}

		results, success := runSingleTarget(*target, proto, &baseConfig)
		allResults = results
		hasSuccess = success

		// Output for single-target mode
		if *jsonOutput {
			outputJSONL(jsonWriter, results)
		} else {
			outputHuman(results, useColor, *quiet)
		}
	}

	// Final JSON output for stdin mode
	if *jsonOutput && useStdin {
		outputJSONL(jsonWriter, allResults)
	}

	// Close output file and exit with appropriate code
	closeOutput()
	if !hasSuccess {
		os.Exit(1)
	}
}

// baseConfigOptions holds common configuration shared across targets
type baseConfigOptions struct {
	usernames         []string
	passwords         []string
	keys              [][]byte
	threads           int
	timeout           time.Duration
	stopOnSuccess     bool
	snmpTier          string
	llmConfig         *brutus.LLMConfig
	browserTimeout    time.Duration
	browserTabs       int
	browserVisible    bool
	useHTTPS          bool
	useColor          bool
	quiet             bool
	verbose           bool
	useBadkeys        bool
	protocolOverride  string              // Override fingerprintx-detected protocol
	aiMode            bool                // Enable AI-powered credential detection for HTTP
	aiVerify          bool                // Use Claude Vision to verify login success
	aiResearchedCreds []brutus.Credential // Credentials researched by LLM for current target
	tlsMode           string              // TLS verification mode: "disable", "verify", "skip-verify"
	rateLimit         float64             // Max requests per second (0 = unlimited)
	jitter            time.Duration       // Random delay variance for rate limiting
	maxAttempts       int
	sprayMode         bool
}

// determineTLSMode returns the appropriate TLS mode based on the verify-tls flag
func determineTLSMode(verifyTLS bool) string {
	if verifyTLS {
		return "verify"
	}
	return "disable"
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

// printBanner displays the ASCII art banner with color
func printBanner(useColor bool) {
	if useColor {
		fmt.Printf("%s%s%s%s\n", ColorBold, ColorRed, banner, ColorReset)
	} else {
		fmt.Printf("%s\n", banner)
	}
}

// printVersion displays version information with color
func printVersion(useColor bool) {
	switch {
	case useColor:
		fmt.Printf("%sBrutus %s%s\n", ColorBold, Version, ColorReset)
		fmt.Printf("  %sBuild time:%s %s\n", ColorCyan, ColorReset, BuildTime)
		fmt.Printf("  %sCommit:%s     %s\n", ColorCyan, ColorReset, CommitSHA)
		fmt.Printf("  %sGo version:%s %s\n", ColorCyan, ColorReset, runtime.Version())
		fmt.Printf("  %sOS/Arch:%s    %s/%s\n", ColorCyan, ColorReset, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Printf("Brutus %s\n", Version)
		fmt.Printf("  Build time: %s\n", BuildTime)
		fmt.Printf("  Commit:     %s\n", CommitSHA)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	}
}

// printTargetInfo displays target configuration details
func printTargetInfo(target, protocol string, base *baseConfigOptions) {
	useColor := base.useColor

	// AI discovery modes - browser uses Vision+Perplexity, HTTP uses Perplexity for Basic Auth
	isBrowserAI := protocol == "browser"
	isHTTPAI := (protocol == "http" || protocol == "https") && base.aiMode && len(base.aiResearchedCreds) > 0
	isAIMode := isBrowserAI || isHTTPAI

	switch {
	case useColor:
		fmt.Printf("\n%s%s %sTarget Information%s\n", ColorCyan, SymbolInfo, ColorBold, ColorReset)
		fmt.Printf("  %sTarget:%s      %s\n", ColorCyan, ColorReset, target)
		fmt.Printf("  %sProtocol:%s    %s\n", ColorCyan, ColorReset, protocol)
		switch {
		case isBrowserAI:
			fmt.Printf("  %sCredentials:%s %sAI Discovery (Claude Vision + Perplexity)%s\n", ColorCyan, ColorReset, ColorPurple, ColorReset)
		case isHTTPAI:
			fmt.Printf("  %sCredentials:%s %sAI Discovery (Perplexity) + admin:admin%s\n", ColorCyan, ColorReset, ColorPurple, ColorReset)
		default:
			fmt.Printf("  %sUsers:%s       %d\n", ColorCyan, ColorReset, len(base.usernames))
			fmt.Printf("  %sPasswords:%s   %d\n", ColorCyan, ColorReset, len(base.passwords))
			if len(base.keys) > 0 {
				fmt.Printf("  %sSSH Keys:%s    %d\n", ColorCyan, ColorReset, len(base.keys))
			}
		}
		if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
			fmt.Printf("  %sLLM:%s         %s%s enabled%s\n", ColorCyan, ColorReset, ColorPurple, base.llmConfig.Provider, ColorReset)
		} else if !isAIMode {
			fmt.Printf("  %sLLM:%s         %sdisabled%s\n", ColorCyan, ColorReset, ColorDim, ColorReset)
		}
		fmt.Printf("  %sThreads:%s     %d\n", ColorCyan, ColorReset, base.threads)
		fmt.Printf("\n")
	default:
		fmt.Printf("\n%s Target Information\n", SymbolInfo)
		fmt.Printf("  Target:      %s\n", target)
		fmt.Printf("  Protocol:    %s\n", protocol)
		switch {
		case isBrowserAI:
			fmt.Printf("  Credentials: AI Discovery (Claude Vision + Perplexity)\n")
		case isHTTPAI:
			fmt.Printf("  Credentials: AI Discovery (Perplexity) + admin:admin\n")
		default:
			fmt.Printf("  Users:       %d\n", len(base.usernames))
			fmt.Printf("  Passwords:   %d\n", len(base.passwords))
			if len(base.keys) > 0 {
				fmt.Printf("  SSH Keys:    %d\n", len(base.keys))
			}
		}
		if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
			fmt.Printf("  LLM:         %s enabled\n", base.llmConfig.Provider)
		} else if !isAIMode {
			fmt.Printf("  LLM:         disabled\n")
		}
		fmt.Printf("  Threads:     %d\n", base.threads)
		fmt.Printf("\n")
	}
}

// customUsage displays custom help message
func customUsage() {
	fmt.Fprintf(os.Stderr, `Brutus - Et tu, Brute?

Usage:
  brutus --target <host:port> --protocol <proto> [options]                # Single target mode
  naabu ... | fingerprintx --json | brutus [options]                      # Pipeline mode (stdin auto-detected)
  naabu ... | fingerprintx --json | brutus --experimental-ai [options]                 # AI-powered credential detection

Target Options:
  --target <host:port>   Target host and port (requires --protocol)
  --stdin                Read targets from stdin (fingerprintx JSON format)
  --protocol <proto>     Protocol to use (auto-detected in pipeline mode)

Credential Options:
  -u <usernames>         Comma-separated usernames (default: "root,admin")
  -p <passwords>         Comma-separated passwords
  -P <file>              Password file (one per line)
  -k <keyfile>           SSH private key file

SSH Options:
  --badkeys              Test embedded bad SSH keys (rapid7/ssh-badkeys, vagrant) [default: true]
  --no-badkeys           Disable embedded bad key testing

Performance Options:
  -t <threads>           Number of concurrent threads (default: 10)
  --timeout <duration>   Per-credential timeout (default: 10s)
  --stop-on-success      Stop after first valid credential (default: true)
  --rate-limit <rps>     Max requests per second (0 = unlimited, default: 0)
  --jitter <duration>    Random delay variance for rate limiting (e.g., 100ms)
  --max-attempts <n>     Max password attempts per user (0 = unlimited, default: 0)
  --spray                Password spraying: try each password across all users

Output Options:
  --json                 JSON output format
  -o <file>              Output file for JSON results (implies --json)
  --banner               Show ASCII banner (default: true)
  --no-color             Disable colored output
  -q                     Quiet mode - only show successful credentials
  -v                     Verbose mode - show detailed progress (to stderr)

SNMP Options:

TLS Options:
  --verify-tls           Require strict TLS certificate verification (default: disabled)
                         Note: Default is no TLS/SSL validation since we're testing
                         default credentials. fingerprintx TLS detection auto-upgrades
                         to skip-verify mode when TLS is detected.
  --snmp-tier <tier>     SNMP community string tier: default (20), extended (50), full (120)

AI Options (automatic credential detection for HTTP services):
  --experimental-ai                          AI-powered credential detection:
                                  - Claude Vision identifies devices and suggests credentials
                                  - Perplexity (optional) searches for additional credentials online

                                  For HTTP Basic Auth: analyzes headers, researches credentials
                                  For form-based login: screenshot analysis + credential research

                                  Requires: ANTHROPIC_API_KEY (Claude Vision)
                                  Optional: PERPLEXITY_API_KEY (additional web search)
                                  (Non-HTTP protocols like SSH are unaffected)
  --experimental-ai-verify                   Use Claude Vision to verify login success by comparing
                                  before/after screenshots (more accurate but slower/costlier)
  --browser-timeout <duration>  Total timeout for browser operations (default: 60s)
  --browser-tabs <n>            Number of concurrent browser tabs (default: 3)
  --browser-visible             Show browser window for debugging/demo (default: headless)
  --https                       Use HTTPS for browser connections

Other Options:
  --version              Show version information
  -h, --help             Show this help message

Fingerprintx Integration:
  Brutus integrates seamlessly with fingerprintx for automated service discovery
  and credential testing. Use naabu for port discovery, fingerprintx for service
  fingerprinting (with --json output), then pipe to Brutus:

    naabu -host <targets> -silent | fingerprintx --json | brutus --stdin [options]

  For known open ports, pipe directly to fingerprintx:

    echo "host:port" | fingerprintx --json | brutus --stdin [options]

  Brutus automatically detects protocols from fingerprintx JSON output,
  eliminating the need to specify -protocol manually.

Supported Protocols:
  Network:      ssh, ftp, telnet, vnc
  Enterprise:   smb, ldap, winrm
  Databases:    mysql, postgresql, mssql, mongodb, redis, neo4j, cassandra,
                couchdb, elasticsearch, influxdb
  NoSQL:        mongodb, redis, neo4j, cassandra, couchdb, elasticsearch, influxdb
  Mail:         smtp, imap, pop3
  Web:          http, https (use --experimental-ai for form-based login pages)
  Other:        snmp

Examples:
  # Scan network range with naabu, fingerprint services, and test credentials
  naabu -host 192.168.1.0/24 -silent | fingerprintx --json | brutus --stdin -P passwords.txt

  # Targeted port scan with service fingerprinting and credential testing
  naabu -host 10.0.0.1 -p 22,3306 -silent | fingerprintx --json | brutus --stdin -u root -p "toor,admin"

  # Fingerprint known open ports and test with private keys
  echo "192.168.1.10:22" | fingerprintx --json | brutus --stdin -u root,ubuntu -k ~/.ssh/id_rsa

  # Single target mode
  brutus --target 192.168.1.10:22 --protocol ssh -p "password,Password1"

  # With LLM-augmented password suggestions (HTTP Basic Auth only)
  brutus --target example.com:80 --protocol http --llm claude

  # SNMP community string testing
  brutus --target 192.168.1.1:161 --protocol snmp --snmp-tier full

  # Quiet mode (only show valid credentials)
  brutus --target 192.168.1.10:22 --protocol ssh -p "pass123" -q

  # SSH with embedded bad keys (enabled by default for SSH)
  brutus --target 192.168.1.10:22 --protocol ssh

  # Disable bad key testing
  brutus --target 192.168.1.10:22 --protocol ssh --no-badkeys -p "password"

  # Pipeline mode with output to file
  naabu -host 10.0.0.0/8 -p 22,3306 -rate 1000 -silent | fingerprintx --json | brutus -t 20 -o findings.json

  # AI-powered credential detection for HTTP services (auto-detects Basic Auth vs form)
  brutus --target 192.168.1.1:80 --protocol http --experimental-ai -u admin -p "admin,password"

  # AI mode in pipeline - auto-login to any HTTP service with default device credentials
  naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | fingerprintx --json | brutus --experimental-ai

`)
}

// runFromStdin reads fingerprintx JSON from stdin and tests each target
func runFromStdin(base *baseConfigOptions, jsonOut bool) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse fingerprintx JSON
		var fpx FingerprintxResult
		if err := json.Unmarshal([]byte(line), &fpx); err != nil {
			if base.useColor {
				fmt.Fprintf(os.Stderr, "%s%s Warning:%s failed to parse JSON: %v%s\n", ColorYellow, SymbolWarning, ColorReset, err, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON: %v\n", err)
			}
			continue
		}

		// Determine protocol: use override if specified, otherwise map from fingerprintx
		var protocol string
		if base.protocolOverride != "" {
			protocol = base.protocolOverride
		} else {
			protocol = mapServiceToProtocol(fpx.Protocol)
			if protocol == "" {
				// Unsupported service, skip
				continue
			}
		}

		// Determine TLS mode for this specific target
		targetTLSMode := base.tlsMode
		if targetTLSMode == "disable" {
			if metadata, ok := fpx.Metadata["tls"]; ok {
				// If TLS is detected in metadata, auto-upgrade to skip-verify
				if tlsEnabled, ok := metadata.(bool); ok && tlsEnabled {
					targetTLSMode = "skip-verify"
					if base.verbose {
						fmt.Fprintf(os.Stderr, "[verbose] TLS detected in fingerprintx metadata, auto-upgrading to skip-verify mode\n")
					}
				}
			}
		}

		// Build target string
		target := fmt.Sprintf("%s:%d", fpx.IP, fpx.Port)

		// AI mode: For HTTP services, detect auth type and route appropriately
		if base.aiMode && (protocol == "http" || protocol == "https") {
			useHTTPS := protocol == "https"
			authType, banner := detectHTTPAuthTypeWithBanner(target, useHTTPS, base.timeout, base.verbose)
			if authType == "basic" {
				// HTTP Basic Auth detected - use LLM to research credentials
				if base.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s uses Basic Auth, using LLM analysis\n", target)
				}

				// Research credentials using LLM
				if base.llmConfig != nil && base.llmConfig.Enabled {
					creds := researchCredentialsWithLLM(target, banner, base.llmConfig, base.verbose)
					if len(creds) > 0 {
						// Add researched credentials to base config for this target
						base.aiResearchedCreds = creds
						if base.verbose {
							fmt.Fprintf(os.Stderr, "[verbose] LLM researched %d credential pairs for %s\n", len(creds), target)
						}
					}
				}
				// Keep http/https protocol
			} else {
				// No Basic Auth - likely form-based, use browser protocol
				if base.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s appears form-based, using browser automation\n", target)
				}
				protocol = "browser"
			}
		}

		// Temporarily set TLS mode for this target, then restore
		originalTLSMode := base.tlsMode
		base.tlsMode = targetTLSMode

		// Run against this target
		results, success := runSingleTarget(target, protocol, base)

		// Restore original TLS mode to prevent mutation across targets
		base.tlsMode = originalTLSMode
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}

		// Output valid credentials immediately (streaming for large-scale scans)
		if !jsonOut {
			outputValidOnly(results, base.useColor)
		}
	}

	if err := scanner.Err(); err != nil {
		if base.useColor {
			fmt.Fprintf(os.Stderr, "%s%s Error:%s reading stdin: %v%s\n", ColorRed, SymbolError, ColorReset, err, ColorReset)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		}
	}

	return allResults, hasSuccess
}

// runSingleTarget runs brutus against a single target
func runSingleTarget(target, protocol string, base *baseConfigOptions) ([]brutus.Result, bool) {
	config := &brutus.Config{
		Target:        target,
		Protocol:      protocol,
		Usernames:     base.usernames,
		Passwords:     base.passwords,
		Keys:          base.keys,
		UseDefaults:   true,
		NoBadkeys:     !base.useBadkeys,
		Threads:       base.threads,
		Timeout:       base.timeout,
		StopOnSuccess: base.stopOnSuccess,
		LLMConfig:     base.llmConfig,
		TLSMode:       base.tlsMode,
		RateLimit:     base.rateLimit,
		Jitter:        base.jitter,
		MaxAttempts:   base.maxAttempts,
		SprayMode:     base.sprayMode,
	}

	// Handle SNMP-specific tier selection (tiers are CLI-only, not in library defaults)
	if protocol == "snmp" && len(config.Passwords) == 0 {
		if !snmp.ValidateTier(base.snmpTier) {
			if base.useColor {
				fmt.Fprintf(os.Stderr, "%s%s Error:%s invalid --snmp-tier: %s (use: default, extended, full)%s\n",
					ColorRed, SymbolError, ColorReset, base.snmpTier, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: invalid --snmp-tier: %s (use: default, extended, full)\n", base.snmpTier)
			}
			return nil, false
		}
		config.Passwords = snmp.GetCommunityStrings(snmp.Tier(base.snmpTier))
	}

	// Handle HTTP with AI-researched credentials
	if (protocol == "http" || protocol == "https") && len(base.aiResearchedCreds) > 0 {
		// Clear default usernames/passwords - use only AI-discovered paired credentials
		config.Usernames = nil
		config.Passwords = nil

		// Add AI-researched credentials
		config.Credentials = append(config.Credentials, base.aiResearchedCreds...)

		// Add admin:admin as basic fallback
		config.Credentials = append(config.Credentials, brutus.Credential{
			Username: "admin",
			Password: "admin",
		})

		if base.verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Using %d AI-researched credentials for HTTP (+ admin:admin fallback)\n", len(base.aiResearchedCreds))
		}

		// Disable LLM in config to prevent duplicate analysis in brutus.go
		config.LLMConfig = nil

		// Clear researched creds so they don't leak to next target
		base.aiResearchedCreds = nil
	}

	// Handle browser-specific configuration
	// Browser protocol requires AI mode - it's the AI-powered form authentication feature
	if protocol == "browser" {
		config.Threads = base.browserTabs
		config.Timeout = base.browserTimeout

		// Clear default usernames/passwords - browser uses AI-discovered paired credentials only
		config.Usernames = nil
		config.Passwords = nil

		// Use Claude Vision + Perplexity for credential research
		// Also get the configured browser plugin to use during brute force
		aiCreds, browserPlugin := researchBrowserCredentials(target, base)
		if len(aiCreds) > 0 {
			config.Credentials = append(config.Credentials, aiCreds...)
			if base.verbose {
				fmt.Fprintf(os.Stderr, "[verbose] AI researched %d credentials for browser\n", len(aiCreds))
			}
		}
		// Pass the configured plugin to Brute (so it has VisionAnalyzer, AIVerify, etc.)
		if browserPlugin != nil {
			config.Plugin = browserPlugin
		}
	}

	// Verbose: print config summary before starting
	if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Target: %s (protocol: %s)\n", target, protocol)
		fmt.Fprintf(os.Stderr, "[verbose] Paired credentials: %d, Usernames: %d, Passwords: %d, Keys: %d\n",
			len(config.Credentials), len(config.Usernames), len(config.Passwords), len(config.Keys))
		// Calculate total attempts
		totalAttempts := len(config.Credentials)
		if len(config.Passwords) > 0 {
			totalAttempts += len(config.Usernames) * len(config.Passwords)
		}
		if len(config.Keys) > 0 {
			totalAttempts += len(config.Usernames) * len(config.Keys)
		}
		fmt.Fprintf(os.Stderr, "[verbose] Total attempts: %d, Threads: %d, Timeout: %s\n",
			totalAttempts, config.Threads, config.Timeout)
		fmt.Fprintf(os.Stderr, "[verbose] Starting brute force...\n")
	}

	// Run brute force
	results, err := brutus.Brute(config)
	if err != nil {
		if base.useColor {
			fmt.Fprintf(os.Stderr, "%s%s Error:%s testing %s: %v%s\n", ColorRed, SymbolError, ColorReset, target, err, ColorReset)
		} else {
			fmt.Fprintf(os.Stderr, "Error testing %s: %v\n", target, err)
		}
		return nil, false
	}

	// Check for success
	hasSuccess := false
	successCount := 0
	for i := range results {
		if results[i].Success {
			hasSuccess = true
			successCount++
		}
	}

	// Verbose: print completion summary
	if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Completed: %d results, %d successful\n", len(results), successCount)
	}

	return results, hasSuccess
}

// mapServiceToProtocol maps fingerprintx service names to brutus protocol names
func mapServiceToProtocol(service string) string {
	// Normalize to lowercase
	service = strings.ToLower(service)

	// Direct mappings
	serviceMap := map[string]string{
		// Network services
		"ssh":    "ssh",
		"ftp":    "ftp",
		"telnet": "telnet",
		"vnc":    "vnc",

		// Enterprise
		"smb":  "smb",
		"ldap": "ldap",

		// Databases
		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"postgres":      "postgresql",
		"mssql":         "mssql",
		"mongodb":       "mongodb",
		"redis":         "redis",
		"neo4j":         "neo4j",
		"cassandra":     "cassandra",
		"couchdb":       "couchdb",
		"elasticsearch": "elasticsearch",
		"influxdb":      "influxdb",

		// Communications
		"smtp": "smtp",
		"imap": "imap",
		"pop3": "pop3",

		// SNMP
		"snmp": "snmp",

		// HTTP - map to our http basic auth plugin
		"http":  "http",
		"https": "https",

		// Browser - headless browser for form-based auth
		"browser": "browser",
	}

	if proto, ok := serviceMap[service]; ok {
		return proto
	}

	return ""
}

// detectHTTPAuthTypeWithBanner probes an HTTP target to determine the authentication type.
// Returns auth type ("basic", "form", or "" if not HTTP) and the banner text for LLM analysis.
func detectHTTPAuthTypeWithBanner(target string, useHTTPS bool, timeout time.Duration, verbose bool) (authType, banner string) {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, target)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] HTTP probe error creating request: %v\n", err)
		}
		return "", "" // Not HTTP or error
	}

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] HTTP probe error: %v\n", err)
		}
		return "", "" // Not HTTP or error
	}
	defer resp.Body.Close()

	// Build banner from response headers and body
	var bannerBuilder strings.Builder
	bannerBuilder.WriteString(fmt.Sprintf("HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status))

	// Include relevant headers
	for _, header := range []string{"Server", "WWW-Authenticate", "X-Powered-By", "X-Server", "X-AspNet-Version"} {
		if val := resp.Header.Get(header); val != "" {
			bannerBuilder.WriteString(fmt.Sprintf("%s: %s\n", header, val))
		}
	}

	// Read body (limited to avoid memory issues)
	body := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, body)
	if n > 0 {
		bannerBuilder.WriteString("\n")
		bannerBuilder.Write(body[:n])
	}

	banner = bannerBuilder.String()

	// Check for WWW-Authenticate header (indicates Basic Auth)
	if authHeader := resp.Header.Get("WWW-Authenticate"); authHeader != "" {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] HTTP probe: WWW-Authenticate header found: %s\n", authHeader)
		}
		return "basic", banner
	}

	// Check for 401 status without WWW-Authenticate (some servers don't send it)
	if resp.StatusCode == http.StatusUnauthorized {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] HTTP probe: 401 without WWW-Authenticate, assuming basic\n")
		}
		return "basic", banner
	}

	return "form", banner
}

// researchBrowserCredentials uses Claude Vision + Perplexity for browser-based credential research.
// 1. Claude Vision analyzes the screenshot to identify the application
// 2. Perplexity researches default credentials for the identified application
// Returns the researched credentials AND the configured browser plugin (for use in Brute).
func researchBrowserCredentials(target string, base *baseConfigOptions) ([]brutus.Credential, *browser.Plugin) {
	if base.llmConfig == nil || !base.llmConfig.Enabled {
		return nil, nil
	}

	// Get API keys
	perplexityKey := os.Getenv("PERPLEXITY_API_KEY")
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

	// Create the browser plugin with configured analyzers
	browserPlugin := &browser.Plugin{
		Timeout:         60 * time.Second,
		TabCount:        base.browserTabs,
		PageLoadTimeout: 15 * time.Second,
		UseHTTPS:        base.useHTTPS,
		Visible:         base.browserVisible,
		Verbose:         base.verbose,
		AIVerify:        base.aiVerify,
	}

	// Configure Vision analyzer (Claude) for screenshot analysis
	if anthropicKey != "" {
		browserPlugin.VisionAnalyzer = &vision.Client{
			APIKey: anthropicKey,
		}
		if base.verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Configured Claude Vision for screenshot analysis\n")
		}
	} else if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] No ANTHROPIC_API_KEY - skipping vision analysis\n")
	}

	// Configure Credential researcher (Perplexity) for default credential lookup
	if perplexityKey != "" {
		factory := brutus.GetAnalyzerFactory("perplexity")
		if factory != nil {
			analyzer := factory(&brutus.LLMConfig{
				Enabled:  true,
				Provider: "perplexity",
				APIKey:   perplexityKey,
			})
			if credAnalyzer, ok := analyzer.(brutus.CredentialAnalyzer); ok {
				browserPlugin.CredentialResearcher = credAnalyzer
				if base.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] Configured Perplexity for credential research\n")
				}
			}
		}
	} else if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] No PERPLEXITY_API_KEY - skipping credential research\n")
	}

	// Call AnalyzePage to do the full two-stage AI flow
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Starting headless browser (this may take a few seconds on first run)...\n")
	}

	pageAnalysis, credentials, err := browserPlugin.AnalyzePage(ctx, target)
	if err != nil {
		if base.verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Page analysis error: %v\n", err)
		}
		return nil, nil
	}

	// Log analysis results
	if base.verbose && pageAnalysis != nil {
		fmt.Fprintf(os.Stderr, "[verbose] Vision detected: %s %s %s (login page: %v, confidence: %.2f)\n",
			pageAnalysis.Application.Vendor,
			pageAnalysis.Application.Model,
			pageAnalysis.Application.Type,
			pageAnalysis.IsLoginPage,
			pageAnalysis.Confidence)
	}

	if len(credentials) > 0 && base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] AI researched %d credential pairs:\n", len(credentials))
		for _, c := range credentials {
			fmt.Fprintf(os.Stderr, "[verbose]   %s:%s\n", c.Username, c.Password)
		}
	}

	return credentials, browserPlugin
}

// researchCredentialsWithLLM uses the configured LLM to research default credentials for a target
func researchCredentialsWithLLM(target, banner string, llmConfig *brutus.LLMConfig, verbose bool) []brutus.Credential {
	if llmConfig == nil || !llmConfig.Enabled {
		return nil
	}

	// Get the analyzer factory for the configured provider
	factory := brutus.GetAnalyzerFactory(llmConfig.Provider)
	if factory == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] LLM analyzer not found for provider: %s\n", llmConfig.Provider)
		}
		return nil
	}
	analyzer := factory(llmConfig)

	// Check if analyzer supports credential pairs (CredentialAnalyzer interface)
	credAnalyzer, ok := analyzer.(brutus.CredentialAnalyzer)
	if !ok {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] LLM analyzer doesn't support credential pairs, using password-only\n")
		}
		// Fall back to password-only analysis
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		bannerInfo := brutus.BannerInfo{
			Protocol: "http",
			Target:   target,
			Banner:   banner,
		}

		passwords, err := analyzer.Analyze(ctx, bannerInfo)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] LLM analysis error: %v\n", err)
			}
			return nil
		}

		// Convert passwords to credentials with common usernames
		var creds []brutus.Credential
		for _, pwd := range passwords {
			creds = append(creds,
				brutus.Credential{Username: "admin", Password: pwd},
				brutus.Credential{Username: "root", Password: pwd})
		}
		return creds
	}

	// Use CredentialAnalyzer for full username:password pairs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bannerInfo := brutus.BannerInfo{
		Protocol: "http",
		Target:   target,
		Banner:   banner,
	}

	creds, err := credAnalyzer.AnalyzeCredentials(ctx, bannerInfo)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] LLM credential analysis error: %v\n", err)
		}
		return nil
	}

	if verbose && len(creds) > 0 {
		fmt.Fprintf(os.Stderr, "[verbose] LLM suggested credentials:\n")
		for _, c := range creds {
			fmt.Fprintf(os.Stderr, "[verbose]   %s:%s\n", c.Username, c.Password)
		}
	}

	return creds
}

func loadPasswords(inline, file string, inlineFlagSet bool) []string {
	var passwords []string

	// Load from inline flag
	if inlineFlagSet {
		passwords = append(passwords, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening password file: %v\n", err)
			os.Exit(1)
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			// Skip comments
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			// Support <EMPTY> marker for empty passwords
			if trimmed == "<EMPTY>" {
				passwords = append(passwords, "")
				continue
			}
			// Include all non-comment lines (empty lines = empty passwords)
			passwords = append(passwords, trimmed)
		}

		scanErr := scanner.Err()
		f.Close()

		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", scanErr)
			os.Exit(1)
		}
	}

	return passwords
}

func loadKey(keyFile string) [][]byte {
	if keyFile == "" {
		return nil
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file %s: %v\n", keyFile, err)
		os.Exit(1)
	}

	return [][]byte{key}
}

func outputHuman(results []brutus.Result, useColor, quiet bool) {
	validCount := 0
	invalidCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Success:
			validCount++
			if useColor {
				fmt.Printf("%s[+] VALID: %s %s:%s @ %s (%s)%s\n",
					ColorGreen, r.Protocol, r.Username, r.Password, r.Target, r.Duration, ColorReset)
				if r.LLMSuggested {
					fmt.Printf("    %s(LLM-suggested)%s\n", ColorPurple, ColorReset)
				}
			} else {
				fmt.Printf("[+] VALID: %s %s:%s @ %s (%s)\n",
					r.Protocol, r.Username, r.Password, r.Target, r.Duration)
				if r.LLMSuggested {
					fmt.Printf("    (LLM-suggested)\n")
				}
			}
		case r.Error != nil:
			errorCount++
			if !quiet && errorCount <= 5 {
				if useColor {
					fmt.Printf("%s%s ERROR:%s %s:%s @ %s - %v%s\n",
						ColorRed, SymbolError, ColorReset, r.Username, r.Password, r.Target, r.Error, ColorReset)
				} else {
					fmt.Printf("[-] ERROR: %s:%s @ %s - %v\n",
						r.Username, r.Password, r.Target, r.Error)
				}
			}
		default:
			invalidCount++
		}
	}

	// Summary (skip in quiet mode unless there are valid credentials)
	if !quiet || validCount > 0 {
		if useColor {
			fmt.Printf("\n%sResults Summary%s\n", ColorBold, ColorReset)
			if validCount > 0 {
				fmt.Printf("  %sValid:%s     %d\n", ColorGreen, ColorReset, validCount)
			}
			if invalidCount > 0 {
				fmt.Printf("  %sInvalid:%s   %d\n", ColorDim, ColorReset, invalidCount)
			}
			if errorCount > 0 {
				fmt.Printf("  %sErrors:%s    %d\n", ColorRed, ColorReset, errorCount)
			}
			fmt.Printf("  %sTotal:%s     %d\n", ColorCyan, ColorReset, len(results))
		} else {
			fmt.Printf("Results: %d valid, %d invalid, %d errors (total: %d)\n",
				validCount, invalidCount, errorCount, len(results))
		}

		if errorCount > 5 {
			if useColor {
				fmt.Printf("\n%s%s Suppressed %d additional errors%s\n", ColorYellow, SymbolWarning, errorCount-5, ColorReset)
			} else {
				fmt.Printf("(Suppressed %d additional errors)\n", errorCount-5)
			}
		}
	}
}

// outputValidOnly prints only successful credentials (for pipeline/large-scale scanning)
func outputValidOnly(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		if r.Success {
			// Simple, parseable format: protocol username:password@target or protocol username:key@target
			cred := r.Username
			if r.Password != "" {
				cred += ":" + r.Password
			} else if len(r.Key) > 0 {
				cred += ":key"
			}
			if useColor {
				fmt.Printf("%s%s %s@%s%s\n", ColorGreen, r.Protocol, cred, r.Target, ColorReset)
			} else {
				fmt.Printf("%s %s@%s\n", r.Protocol, cred, r.Target)
			}
		}
	}
}

// outputJSONL streams successful results as JSONL (one JSON object per line)
// This matches the output format of naabu and fingerprintx for easy piping
func outputJSONL(w io.Writer, results []brutus.Result) {
	type JSONResult struct {
		Protocol     string `json:"protocol"`
		Target       string `json:"target"`
		Username     string `json:"username"`
		Password     string `json:"password,omitempty"`
		Key          bool   `json:"key,omitempty"`
		Duration     string `json:"duration"`
		Banner       string `json:"banner,omitempty"`
		LLMSuggested bool   `json:"llm_suggested,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		if !r.Success {
			continue // Only output successful auths
		}
		jr := JSONResult{
			Protocol:     r.Protocol,
			Target:       r.Target,
			Username:     r.Username,
			Password:     r.Password,
			Key:          len(r.Key) > 0,
			Duration:     r.Duration.String(),
			Banner:       r.Banner,
			LLMSuggested: r.LLMSuggested,
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	}
}
