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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/internal/plugins/snmp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// runFromStdin reads nerva JSON from stdin and tests each target
func runFromStdin(base *baseConfigOptions, jsonOut bool) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse nerva JSON
		var nrv brutus.NervaResult
		if err := json.Unmarshal([]byte(line), &nrv); err != nil {
			warnMsg(base.useColor, "failed to parse JSON: %v", err)
			continue
		}

		// Determine protocol: use override if specified, otherwise map from nerva
		var protocol string
		if base.protocolOverride != "" {
			protocol = base.protocolOverride
		} else {
			protocol = brutus.MapServiceToProtocol(nrv.Protocol)
			if protocol == "" {
				// Unsupported service, skip
				continue
			}
		}

		// --badkeys-only: skip non-SSH targets entirely
		if base.badkeysOnly && protocol != "ssh" {
			continue
		}

		// Determine TLS mode for this specific target
		targetTLSMode := detectTLS(base.tlsMode, nrv.TLS, base.verbose)

		// Build target string
		target := fmt.Sprintf("%s:%d", nrv.IP, nrv.Port)
		if nrv.Host != "" {
			target = fmt.Sprintf("%s:%d", nrv.Host, nrv.Port)
		}

		// AI mode: For HTTP services, detect auth type and route appropriately
		var aiCreds []brutus.Credential
		if base.aiMode && (protocol == "http" || protocol == "https") {
			protocol, aiCreds = routeHTTPWithAI(target, protocol, base)
		}

		// Run against this target
		results, success := runSingleTarget(target, protocol, targetTLSMode, base, aiCreds)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}

		// Output valid credentials immediately (streaming for large-scale scans)
		if !jsonOut {
			outputValidOnly(results, base.useColor)
			// Also output security findings (e.g., sticky keys detection)
			for i := range results {
				r := &results[i]
				if r.Banner != "" && hasSecurityFinding(r.Banner) {
					if base.useColor {
						fmt.Printf("\n%s\n", heading(base.useColor, "Security Findings"))
						fmt.Printf("  %s @ %s\n", r.Protocol, r.Target)
						for _, line := range splitLines(r.Banner) {
							fmt.Printf("  %s\n", line)
						}
					} else {
						fmt.Printf("%s @ %s: %s\n", r.Protocol, r.Target, r.Banner)
					}
					break // One findings block per target
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		errMsg(base.useColor, "reading stdin: %v", err)
	}

	return allResults, hasSuccess
}

// runSingleTarget runs brutus against a single target
func runSingleTarget(target, protocol, tlsMode string, base *baseConfigOptions, aiCreds []brutus.Credential) ([]brutus.Result, bool) {
	config := &brutus.Config{
		Target:        target,
		Protocol:      protocol,
		Usernames:     base.usernames,
		Passwords:     base.passwords,
		Keys:          base.keys,
		UseDefaults:   true,
		NoBadkeys:     !base.useBadkeys,
		BadkeysOnly:   base.badkeysOnly,
		Threads:       base.threads,
		Timeout:       base.timeout,
		StopOnSuccess: base.stopOnSuccess,
		LLMConfig:     base.llmConfig,
		TLSMode:       tlsMode,
		RateLimit:     base.rateLimit,
		Jitter:        base.jitter,
		MaxAttempts:   base.maxAttempts,
		SprayMode:     base.sprayMode,
		MaxRetries:    base.maxRetries,
		Verbose:       base.verbose,
	}

	// Handle SNMP-specific tier selection (tiers are CLI-only, not in library defaults)
	if protocol == "snmp" && len(config.Passwords) == 0 {
		if err := configureSNMP(config, base); err != nil {
			errMsg(base.useColor, "%v", err)
			return nil, false
		}
	}

	// Handle HTTP with AI-researched credentials
	if (protocol == "http" || protocol == "https") && len(aiCreds) > 0 {
		configureAICredentials(config, aiCreds, base.verbose)
	}

	// Handle browser-specific configuration
	if protocol == "browser" {
		if err := configureBrowser(config, target, base); err != nil {
			errMsg(base.useColor, "%v", err)
			return nil, false
		}
	}

	// Sticky keys interactive modes: bypass brute force entirely
	if protocol == "rdp" && base.stickyKeys && (base.stickyKeysExec != "" || base.stickyKeysWeb) {
		return runStickyKeysInteractive(target, protocol, base)
	}

	// Verbose: print config summary before starting
	logVerbose(base.verbose, "Target: %s (protocol: %s)", target, protocol)
	logVerbose(base.verbose, "Paired credentials: %d, Usernames: %d, Passwords: %d, Keys: %d",
		len(config.Credentials), len(config.Usernames), len(config.Passwords), len(config.Keys))
	totalAttempts := len(config.Credentials)
	if len(config.Passwords) > 0 {
		totalAttempts += len(config.Usernames) * len(config.Passwords)
	}
	if len(config.Keys) > 0 {
		totalAttempts += len(config.Usernames) * len(config.Keys)
	}
	logVerbose(base.verbose, "Total attempts: %d, Threads: %d, Timeout: %s",
		totalAttempts, config.Threads, config.Timeout)
	logVerbose(base.verbose, "Starting brute force...")

	// Create context that cancels on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Propagate RDP sticky keys flags via context (not env vars)
	// Vision API requires --experimental-ai; disable it otherwise
	if !base.aiMode {
		ctx = brutus.ContextWithNoVision(ctx)
	}
	if !base.stickyKeys {
		ctx = brutus.ContextWithNoStickyKeys(ctx)
	}

	// Run brute force with context
	results, err := brutus.BruteWithContext(ctx, config)
	if err != nil {
		errMsg(base.useColor, "testing %s: %v", target, err)
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
	logVerbose(base.verbose, "Completed: %d results, %d successful", len(results), successCount)

	return results, hasSuccess
}

// configureSNMP validates SNMP tier and sets community string passwords on the config.
func configureSNMP(config *brutus.Config, base *baseConfigOptions) error {
	if !snmp.ValidateTier(base.snmpTier) {
		return fmt.Errorf("invalid --snmp-tier: %s (use: default, extended, full)", base.snmpTier)
	}
	config.Passwords = snmp.GetCommunityStrings(snmp.Tier(base.snmpTier))
	return nil
}

// configureAICredentials applies AI-researched credentials to the config, replacing defaults.
func configureAICredentials(config *brutus.Config, aiCreds []brutus.Credential, verbose bool) {
	config.Usernames = nil
	config.Passwords = nil
	config.Credentials = append(config.Credentials, aiCreds...)
	config.Credentials = append(config.Credentials, brutus.Credential{
		Username: "admin",
		Password: "admin",
	})
	logVerbose(verbose, "Using %d AI-researched credentials for HTTP (+ admin:admin fallback)", len(aiCreds))
	config.LLMConfig = nil
}

// detectTLS checks if TLS was detected by nerva and upgrades the TLS mode.
func detectTLS(baseTLSMode string, tlsDetected, verbose bool) string {
	if baseTLSMode != "disable" {
		return baseTLSMode
	}
	if tlsDetected {
		logVerbose(verbose, "TLS detected by nerva, auto-upgrading to skip-verify mode")
		return "skip-verify"
	}
	return baseTLSMode
}

// configureBrowser sets up browser-specific configuration including AI credential research.
func configureBrowser(config *brutus.Config, target string, base *baseConfigOptions) error {
	config.Threads = base.browserTabs
	config.Timeout = base.browserTimeout
	config.Usernames = nil
	config.Passwords = nil
	creds, browserPlugin := researchBrowserCredentials(target, base)
	if len(creds) > 0 {
		config.Credentials = append(config.Credentials, creds...)
		logVerbose(base.verbose, "AI researched %d credentials for browser", len(creds))
	}
	if browserPlugin != nil {
		config.Plugin = browserPlugin
	}
	if len(config.Credentials) == 0 && config.Plugin == nil {
		return fmt.Errorf("browser mode: no credentials discovered and no browser plugin configured for %s", target)
	}
	return nil
}

// runStickyKeysInteractive handles the --sticky-keys-exec and --sticky-keys-web modes.
// These bypass normal brute force and instead exploit the sticky keys backdoor interactively.
func runStickyKeysInteractive(target, protocol string, base *baseConfigOptions) ([]brutus.Result, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result := brutus.Result{
		Protocol: protocol,
		Target:   target,
		Username: "(sticky-keys)",
	}

	if base.stickyKeysWeb {
		err := rdp.RunWebTerminal(ctx, target, base.timeout, base.stickyKeysOpen)
		if err != nil && err != http.ErrServerClosed {
			errMsg(base.useColor, "web terminal: %v", err)
			result.Error = err
			return []brutus.Result{result}, false
		}
		result.Success = true
		result.Banner = "[INFO] Web terminal session ended"
		return []brutus.Result{result}, true
	}

	if base.stickyKeysExec != "" {
		var execAPIKey string
		if base.aiMode {
			execAPIKey = base.anthropicKey
		}
		execResult := rdp.RunStickyKeysExec(ctx, target, base.stickyKeysExec, base.timeout, execAPIKey)
		if execResult.Error != "" {
			errMsg(base.useColor, "sticky keys exec: %s", execResult.Error)
			result.Error = fmt.Errorf("%s", execResult.Error)
			return []brutus.Result{result}, false
		}
		result.Success = execResult.BackdoorDetected
		if execResult.Output != "" {
			result.Banner = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, output:\n%s",
				execResult.BackdoorDetected, execResult.Output)
		} else {
			result.Banner = fmt.Sprintf("[INFO] Sticky keys exec: backdoor=%v, screenshot=%s",
				execResult.BackdoorDetected, execResult.ScreenshotPath)
		}
		return []brutus.Result{result}, execResult.BackdoorDetected
	}

	return nil, false
}

// runScanFromStdin reads nerva JSON from stdin and runs scan checks on RDP targets.
func runScanFromStdin(base *baseConfigOptions) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var nrv brutus.NervaResult
		if err := json.Unmarshal([]byte(line), &nrv); err != nil {
			warnMsg(base.useColor, "failed to parse JSON: %v", err)
			continue
		}

		// Filter to RDP targets only
		protocol := brutus.MapServiceToProtocol(nrv.Protocol)
		if protocol != "rdp" && base.protocolOverride != "rdp" {
			continue
		}

		target := fmt.Sprintf("%s:%d", nrv.IP, nrv.Port)
		if nrv.Host != "" {
			target = fmt.Sprintf("%s:%d", nrv.Host, nrv.Port)
		}
		results, success := runScanSingleTarget(target, base)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}
	}

	if err := scanner.Err(); err != nil {
		errMsg(base.useColor, "reading stdin: %v", err)
	}

	return allResults, hasSuccess
}

// runScanSingleTarget runs sticky keys detection on a single target.
func runScanSingleTarget(target string, base *baseConfigOptions) ([]brutus.Result, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Vision API requires --experimental-ai; disable it otherwise
	if !base.aiMode {
		ctx = brutus.ContextWithNoVision(ctx)
	}

	result := rdp.DetectStickyKeys(ctx, target, base.timeout, "(sticky-keys)")
	results := []brutus.Result{*result}
	hasSuccess := result.Success

	return results, hasSuccess
}
