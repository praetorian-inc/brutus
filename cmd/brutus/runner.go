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
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

// runFromTargetsFile iterates the host:port lines from a targets file and
// runs the configured brute force against each one. Order matches the file;
// a per-target failure does not abort the whole run.
//
// Output behavior mirrors --nerva (multi-target) mode: in human output we
// stream "valid only" findings per target as soon as they're produced, and
// in JSON mode the caller flushes the full JSONL after the loop returns.
//
// See https://github.com/praetorian-inc/brutus/issues/80.
func runFromTargetsFile(targets []string, base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false

	for _, target := range targets {
		if base.protocolOverride == "" {
			warnMsg(base.useColor, "skipping %q: --protocol is required when using --targets-file", target)
			continue
		}
		protocol := base.protocolOverride

		// Apply subcommand protocol filter
		if base.protocolFilter != nil && !base.protocolFilter(protocol) {
			continue
		}

		// Detect HTTP auth type for web subcommand (form-based → browser protocol).
		var aiCreds []brutus.Credential
		if base.web != nil && (protocol == "http" || protocol == "https") {
			protocol, aiCreds = web.RouteHTTP(target, protocol, base.timeout, base.tlsMode, base.llmConfig)
		}

		if !jsonOut && !base.quiet {
			printTargetInfo(target, protocol, base, aiCreds)
		}

		results, success := runSingleTarget(target, protocol, base.tlsMode, base, aiCreds, false)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}

		if !jsonOut {
			outputValidOnly(results, base.useColor)
			emitSecurityFindings(results, base.useColor)
		}
	}

	return allResults, hasSuccess
}

// emitSecurityFindings prints the per-target Security-Findings block for any
// result whose banner carries a security-relevant marker (sticky-keys, etc.).
// Extracted so runFromStdin and runFromTargetsFile share one implementation
// rather than duplicating the streaming-output path.
func emitSecurityFindings(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		if r.Banner == "" || !hasSecurityFinding(r.Banner) {
			continue
		}
		if useColor {
			fmt.Printf("\n%s\n", heading(useColor, "Security Findings"))
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

// runFromStdin reads targets from stdin and tests each one. It accepts three
// line formats: Nerva JSON ({"ip":...}), URI scheme (ssh://host:port), and
// bare host:port. JSON and URI lines are processed immediately (streaming).
// Bare host:port lines are collected and batch-fingerprinted with Nerva after
// stdin is exhausted.
func runFromStdin(base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false
	var bareTargets []string

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := brutusinput.ClassifyStdinLine(line)
		if err != nil {
			warnMsg(base.useColor, "skipping %q: %v", line, err)
			continue
		}

		switch parsed.Type {
		case brutusinput.StdinLineJSON:
			results, success := processNervaResult(&parsed.NervaResult, base, jsonOut)
			allResults = append(allResults, results...)
			if success {
				hasSuccess = true
			}

		case brutusinput.StdinLineURI:
			results, success := processURITarget(&parsed, base, jsonOut)
			allResults = append(allResults, results...)
			if success {
				hasSuccess = true
			}

		case brutusinput.StdinLineHostPort:
			bareTargets = append(bareTargets, parsed.Raw)
		}
	}
	if err := scanner.Err(); err != nil {
		errMsg(base.useColor, "reading stdin: %v", err)
	}

	// Phase 2: batch-fingerprint bare host:port targets via Nerva.
	if len(bareTargets) > 0 {
		fpResults, fpSuccess := runFromFingerprint(bareTargets, base, jsonOut)
		allResults = append(allResults, fpResults...)
		if fpSuccess {
			hasSuccess = true
		}
	}

	return allResults, hasSuccess
}

// processNervaResult handles a single parsed Nerva JSON result: maps protocol,
// applies filters, determines TLS, and runs brute force. Extracted from the
// former runFromStdin loop body for reuse by the line classifier.
func processNervaResult(nrv *brutusinput.NervaResult, base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	// Determine protocol: use override if specified, otherwise map from nerva
	var protocol string
	if base.protocolOverride != "" {
		protocol = base.protocolOverride
	} else {
		protocol = brutusinput.MapServiceToProtocol(nrv.Protocol)
		if protocol == "" {
			return nil, false
		}
	}

	if base.protocolFilter != nil && !base.protocolFilter(protocol) {
		return nil, false
	}

	targetTLSMode := detectTLS(base.tlsMode, nrv.TLS, base.verbose)

	target := nrv.TargetAddr()

	// If Nerva JSON from stdin indicates no auth, report the finding and skip
	// credential testing — every password "works" on a service that doesn't
	// enforce auth, so brute force results would be misleading.
	if nrv.HasNoAuth() {
		logVerbose(base.verbose, "Nerva JSON indicates unauthenticated access on %s (%s) — skipping credential testing", target, protocol)
		finding := brutus.Result{
			Protocol: protocol,
			Target:   target,
			Username: "(unauthenticated)",
			Success:  true,
			Banner:   fmt.Sprintf("[CRITICAL] %s accessible without authentication (detected by Nerva scan)", protocol),
		}
		if !jsonOut {
			emitSecurityFindings([]brutus.Result{finding}, base.useColor)
		}
		return []brutus.Result{finding}, true
	}

	var aiCreds []brutus.Credential
	if base.web != nil && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = web.RouteHTTP(target, protocol, base.timeout, base.tlsMode, base.llmConfig)
	}

	results, success := runSingleTarget(target, protocol, targetTLSMode, base, aiCreds, false)

	if !jsonOut {
		outputValidOnly(results, base.useColor)
		emitSecurityFindings(results, base.useColor)
	}

	return results, success
}

// processURITarget handles a URI-scheme stdin line (e.g. ssh://host:22).
// The protocol is already parsed from the URI scheme; no fingerprinting needed.
func processURITarget(parsed *brutusinput.ParsedStdinLine, base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	protocol := parsed.Protocol
	if base.protocolOverride != "" {
		protocol = base.protocolOverride
	}

	if base.protocolFilter != nil && !base.protocolFilter(protocol) {
		return nil, false
	}

	targetTLSMode := base.tlsMode
	if parsed.TLS && targetTLSMode == "disable" {
		targetTLSMode = "skip-verify"
	}

	target := parsed.HostPort

	var aiCreds []brutus.Credential
	if base.web != nil && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = web.RouteHTTP(target, protocol, base.timeout, base.tlsMode, base.llmConfig)
	}

	if !jsonOut && !base.quiet {
		printTargetInfo(target, protocol, base, aiCreds)
	}

	results, success := runSingleTarget(target, protocol, targetTLSMode, base, aiCreds, false)

	if !jsonOut {
		outputValidOnly(results, base.useColor)
		emitSecurityFindings(results, base.useColor)
	}

	return results, success
}

// isUnauthOnlyProtocol returns true for protocols that only support
// unauthenticated access detection (no credential testing).
// This checks the unauth-only registry rather than hardcoding protocol names.
func isUnauthOnlyProtocol(protocol string) bool {
	_, err := brutus.GetUnauthChecker(protocol)
	return err == nil
}

// runSingleTarget runs brutus against a single target.
func runSingleTarget(target, protocol, tlsMode string, base *runConfig, aiCreds []brutus.Credential, nervaNoAuth bool) ([]brutus.Result, bool) {
	// Unauth-only protocols: run CheckUnauthAccess directly, skip brute force
	if isUnauthOnlyProtocol(protocol) {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		pluginCfg := brutus.PluginConfig{TLSMode: tlsMode, ProxyURL: base.proxyURL}
		r := brutus.CheckUnauthAccess(ctx, target, protocol, base.timeout, pluginCfg)
		if r == nil {
			return nil, false
		}
		return []brutus.Result{*r}, r.Success
	}

	config := &brutus.Config{
		Target:          target,
		Protocol:        protocol,
		Usernames:       base.usernames,
		Passwords:       base.passwords,
		Credentials:     base.credentials,
		Keys:            base.keys,
		UseDefaults:     true,
		NoBadkeys:       !base.useBadkeys,
		BadkeysOnly:     base.badkeysOnly,
		Threads:         base.threads,
		Timeout:         base.timeout,
		LLMConfig:       base.llmConfig,
		TLSMode:         tlsMode,
		RateLimit:       base.rateLimit,
		Jitter:          base.jitter,
		MaxAttempts:     base.maxAttempts,
		MaxRetries:      base.maxRetries,
		Verbose:         base.verbose,
		SkipUnauthCheck: nervaNoAuth,
		Mode:            brutus.NormalizeMode(base.mode),
		ProxyURL:        base.proxyURL,
	}

	// Handle HTTP with AI-researched credentials
	if (protocol == "http" || protocol == "https") && len(aiCreds) > 0 {
		config.Usernames = nil
		config.Passwords = nil
		config.Credentials = web.ConfigureAICredentials(aiCreds)
		config.LLMConfig = nil
		logVerbose(base.verbose, "Using %d AI-researched credentials for HTTP (+ admin:admin fallback)", len(aiCreds))
	}

	// Handle browser-specific configuration
	if protocol == "browser" && base.web != nil {
		config.Threads = base.web.browserTabs
		config.Timeout = base.web.browserTimeout
		config.Usernames = nil
		config.Passwords = nil
		useHTTPS := base.web.useHTTPS || tlsMode == "skip-verify" || tlsMode == "verify"

		// AI credential research (only when AI mode is enabled)
		if base.aiMode {
			browserCreds, browserPlugin, browserErr := web.ResearchBrowserCredentials(context.Background(), target, web.BrowserConfig{
				Tabs:          base.web.browserTabs,
				Timeout:       base.web.browserTimeout,
				UseHTTPS:      useHTTPS,
				Visible:       base.web.browserVisible,
				AIVerify:      true,
				AnthropicKey:  base.anthropicKey,
				PerplexityKey: base.perplexityKey,
				LLMConfig:     base.llmConfig,
			})
			if browserErr != nil {
				errMsg(base.useColor, "browser credential research for %s: %v", target, browserErr)
			}
			if len(browserCreds) > 0 {
				config.Credentials = append(config.Credentials, browserCreds...)
				logVerbose(base.verbose, "AI researched %d credentials for browser", len(browserCreds))
			}
			if browserPlugin != nil {
				config.Plugin = browserPlugin
			}
		}

		// Ensure browser plugin exists (non-AI mode creates a basic one)
		if config.Plugin == nil {
			config.Plugin = web.NewBrowserPlugin(base.web.browserTabs, base.web.browserTimeout, useHTTPS, base.web.browserVisible)
		}

		if len(config.Credentials) == 0 {
			errMsg(base.useColor, "browser mode: no credentials for %s (use -c/-C or --experimental-ai)", target)
			return nil, false
		}
	}

	// Sticky keys interactive modes: bypass brute force entirely
	if protocol == "rdp" && base.logon != nil && (base.logon.execCmd != "" || base.logon.webTerminal) {
		return runStickyKeysInteractive(target, base)
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

	// Set RDP-specific flags on config for the plugin
	if base.logon != nil {
		config.StickyKeys = true
	}
	config.AIMode = base.aiMode

	// Create context that cancels on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

// runStickyKeysInteractive handles the --sticky-keys-exec and --sticky-keys-web modes.
// These bypass normal brute force and instead exploit the sticky keys backdoor interactively.
func runStickyKeysInteractive(target string, base *runConfig) ([]brutus.Result, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if base.logon.webTerminal {
		result, success := logon.RunWebTerminal(ctx, logon.WebTerminalConfig{
			Target:      target,
			Timeout:     base.timeout,
			OpenBrowser: base.logon.openBrowser,
		})
		if !success {
			errMsg(base.useColor, "web terminal: %v", result.Error)
		}
		return []brutus.Result{result}, success
	}

	if base.logon.execCmd != "" {
		result, success := logon.RunExec(ctx, logon.ExecConfig{
			Target:       target,
			Timeout:      base.timeout,
			AIMode:       base.aiMode,
			AnthropicKey: base.anthropicKey,
		}, base.logon.execCmd)
		if !success {
			errMsg(base.useColor, "sticky keys exec: %v", result.Error)
		}
		return []brutus.Result{result}, success
	}

	return nil, false
}

// runScanFromStdin reads targets from stdin and runs scan checks (logon-screen
// backdoor detection) on RDP targets. Accepts the same three line formats as
// runFromStdin: Nerva JSON, URI scheme, and bare host:port.
func runScanFromStdin(base *runConfig) ([]brutus.Result, bool) {
	var scanTargets []string
	var bareTargets []string

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := brutusinput.ClassifyStdinLine(line)
		if err != nil {
			warnMsg(base.useColor, "skipping %q: %v", line, err)
			continue
		}

		switch parsed.Type {
		case brutusinput.StdinLineJSON:
			protocol := brutusinput.MapServiceToProtocol(parsed.NervaResult.Protocol)
			if base.protocolFilter != nil && !base.protocolFilter(protocol) {
				continue
			}
			scanTargets = append(scanTargets, parsed.NervaResult.TargetAddr())

		case brutusinput.StdinLineURI:
			if base.protocolFilter != nil && !base.protocolFilter(parsed.Protocol) {
				continue
			}
			scanTargets = append(scanTargets, parsed.HostPort)

		case brutusinput.StdinLineHostPort:
			bareTargets = append(bareTargets, parsed.Raw)
		}
	}

	if err := scanner.Err(); err != nil {
		errMsg(base.useColor, "reading stdin: %v", err)
	}

	allResults, hasSuccess := runScanTargetsConcurrent(scanTargets, base)

	// Batch-fingerprint bare targets, then scan any discovered RDP services.
	if len(bareTargets) > 0 {
		fpResults, fpSuccess := runLogonFingerprint(bareTargets, base)
		allResults = append(allResults, fpResults...)
		if fpSuccess {
			hasSuccess = true
		}
	}

	return allResults, hasSuccess
}

// runScanSingleTarget runs sticky keys detection on a single target.
func runScanSingleTarget(target string, base *runConfig) ([]brutus.Result, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return scanTargetFn(ctx, target, base)
}

// scanTargetFn performs detection for a single target. It is a package-level
// variable so tests can substitute a fake without a live RDP server.
var scanTargetFn = func(ctx context.Context, target string, base *runConfig) ([]brutus.Result, bool) {
	return logon.DetectBackdoors(ctx, target, base.connectTimeout, base.timeout, base.aiMode, base.maxRetries, base.checks,
		base.proxyURL, base.noNLAProbe, base.fast)
}

// runScanTargetsConcurrent runs sticky-keys/utilman detection across many targets
// in parallel, bounded by base.threads. This is the scan-path equivalent of the
// credential brute-force worker pool (pkg/brutus/workers.go): on the detection path
// --threads controls host-level concurrency, because there is exactly one probe per
// host (credential-level threading does not apply). Results are returned in input
// order so output stays deterministic regardless of completion order.
func runScanTargetsConcurrent(targets []string, base *runConfig) ([]brutus.Result, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScanTargetsConcurrentCtx(ctx, targets, base)
}

// runScanTargetsConcurrentCtx is runScanTargetsConcurrent with an injectable
// context, so tests can drive cancellation without sending real signals.
func runScanTargetsConcurrentCtx(ctx context.Context, targets []string, base *runConfig) ([]brutus.Result, bool) {
	if len(targets) == 0 {
		return nil, false
	}

	threads := base.threads
	if threads < 1 {
		threads = 1
	}

	// RDP decode is CPU-bound and process-wide bounded to ~decodeSlotCount cores
	// (pkg/brutus/logon admission control), so cranking --threads far above that
	// budget adds queueing, not throughput. Warn once on the scan path only.
	if slots := logon.DecodeSlotCount(); int64(threads) > 4*slots {
		warnMsg(base.useColor, "high --threads won't speed up CPU-bound RDP decode; decode is bounded to ~%d cores.", slots)
	}

	// Optional rate limiting across host scans, mirroring the brute-force path.
	// --rate-limit caps how many host scans may start per second (0 = unlimited).
	var limiter *rate.Limiter
	if base.rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(base.rateLimit), 1)
	}

	perTarget := make([][]brutus.Result, len(targets))
	success := make([]bool, len(targets))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)

	for i := range targets {
		idx, target := i, targets[i]
		g.Go(func() error {
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					// Context canceled while queued: the host never ran, so it
					// must read as INDETERMINATE, never silently disappear.
					perTarget[idx] = logon.CancelledResults(target)
					success[idx] = false
					return nil
				}
			}
			if ctx.Err() != nil {
				perTarget[idx] = logon.CancelledResults(target)
				success[idx] = false
				return nil
			}
			results, ok := scanTargetFn(ctx, target, base)
			perTarget[idx] = results
			success[idx] = ok
			return nil
		})
	}
	_ = g.Wait()

	var all []brutus.Result
	hasSuccess := false
	for i := range targets {
		all = append(all, perTarget[i]...)
		if success[i] {
			hasSuccess = true
		}
	}
	return all, hasSuccess
}

// runFromNmapFile loads targets from an nmap XML file and processes each
// discovered service. Nmap provides service identification, so results are
// fed through processNervaResult (same path as Nerva JSON stdin input).
func runFromNmapFile(base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	nmapResults, err := brutusinput.LoadNmapFile(flagNmapFile)
	if err != nil {
		errMsg(base.useColor, "%v", err)
		return nil, false
	}
	if len(nmapResults) == 0 {
		warnMsg(base.useColor, "nmap file %q contains no open ports", flagNmapFile)
		return nil, false
	}

	logVerbose(base.verbose, "Loaded %d open port(s) from nmap file %s", len(nmapResults), flagNmapFile)

	var allResults []brutus.Result
	hasSuccess := false

	for i := range nmapResults {
		nrv := &nmapResults[i]

		// Skip ports where nmap couldn't identify the service.
		if nrv.Protocol == "" {
			logVerbose(base.verbose, "skipping %s:%d — nmap could not identify service",
				nrv.IP, nrv.Port)
			continue
		}

		// When a protocol override is set (from --protocol flag or subcommand
		// like snmp/badkeys/logon), only test ports whose nmap-detected service
		// matches. Without this, "brutus snmp --nmap-file scan.xml" would run
		// SNMP checks against every open port (SSH, HTTP, etc.).
		if base.protocolOverride != "" && nrv.Protocol != base.protocolOverride {
			logVerbose(base.verbose, "skipping %s:%d — nmap service %q doesn't match protocol %q",
				nrv.IP, nrv.Port, nrv.Protocol, base.protocolOverride)
			continue
		}

		res, success := processNervaResult(nrv, base, jsonOut)
		allResults = append(allResults, res...)
		if success {
			hasSuccess = true
		}
	}

	return allResults, hasSuccess
}

// runFromMasscanFile loads targets from a masscan JSON file and processes
// each discovered open port. Because masscan does not fingerprint services,
// targets are handled like bare host:port entries:
//   - If --protocol is set, targets are tested directly with that protocol.
//   - If --protocol is not set, targets are batch-fingerprinted with Nerva.
func runFromMasscanFile(base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	masscanResults, err := brutusinput.LoadMasscanFile(flagMasscanFile)
	if err != nil {
		errMsg(base.useColor, "%v", err)
		return nil, false
	}
	if len(masscanResults) == 0 {
		warnMsg(base.useColor, "masscan file %q contains no open ports", flagMasscanFile)
		return nil, false
	}

	logVerbose(base.verbose, "Loaded %d open port(s) from masscan file %s", len(masscanResults), flagMasscanFile)

	// Convert NervaResults to host:port strings for the existing pipelines.
	targets := make([]string, 0, len(masscanResults))
	for _, nrv := range masscanResults {
		targets = append(targets, nrv.TargetAddr())
	}

	if base.protocolOverride != "" {
		return runFromTargetsFile(targets, base, jsonOut)
	}
	return runFromFingerprint(targets, base, jsonOut)
}

// runScanFromNmapFile loads nmap results and runs logon-screen detection
// on any RDP services found.
func runScanFromNmapFile(base *runConfig) ([]brutus.Result, bool) {
	nmapResults, err := brutusinput.LoadNmapFile(flagNmapFile)
	if err != nil {
		errMsg(base.useColor, "%v", err)
		return nil, false
	}

	var scanTargets []string
	for _, nrv := range nmapResults {
		if nrv.Protocol == "" {
			continue
		}
		if base.protocolFilter != nil && !base.protocolFilter(nrv.Protocol) {
			continue
		}
		scanTargets = append(scanTargets, nrv.TargetAddr())
	}
	return runScanTargetsConcurrent(scanTargets, base)
}

// runScanFromMasscanFile loads masscan results and fingerprints them with
// Nerva, then runs logon-screen detection on any discovered RDP services.
func runScanFromMasscanFile(base *runConfig) ([]brutus.Result, bool) {
	masscanResults, err := brutusinput.LoadMasscanFile(flagMasscanFile)
	if err != nil {
		errMsg(base.useColor, "%v", err)
		return nil, false
	}

	targets := make([]string, 0, len(masscanResults))
	for _, nrv := range masscanResults {
		targets = append(targets, nrv.TargetAddr())
	}

	return runLogonFingerprint(targets, base)
}
