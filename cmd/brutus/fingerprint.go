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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	nervaplugins "github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

// nervaScanConfig builds a Nerva scan.Config from the user's CLI flags,
// falling back to sensible defaults when the flags are at their zero values.
func nervaScanConfig(base *runConfig) scan.Config {
	timeout := base.timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	workers := base.threads
	if workers <= 0 {
		workers = 50
	}
	return scan.Config{
		DefaultTimeout: timeout,
		Workers:        workers,
		Verbose:        base.verbose,
	}
}

// fingerprintedService holds the result of fingerprinting a single target.
type fingerprintedService struct {
	protocol string
	tls      bool
	noAuth   bool // Nerva detected anonymous/unauthenticated access
}

// fingerprintSingleTarget probes a single host:port with Nerva and returns
// the discovered protocol and TLS status. Used when --target is given without
// --protocol so the CLI can auto-detect the service.
func fingerprintSingleTarget(target string, base *runConfig) (*fingerprintedService, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nt, err := brutusinput.ParseNervaTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}

	if !base.quiet {
		fmt.Fprintf(os.Stderr, "%s Fingerprinting %s with Nerva...\n",
			dim(base.useColor, SymbolInfo), target)
	}

	cfg := nervaScanConfig(base)
	cfg.Workers = 1 // single target — one worker is sufficient

	services, err := scan.ScanTargets(ctx, []nervaplugins.Target{nt}, cfg)
	if err != nil {
		return nil, fmt.Errorf("fingerprinting %s: %w", target, err)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("could not fingerprint service on %s", target)
	}

	nrv := brutusinput.ServiceToNervaResult(&services[0])
	protocol := brutusinput.MapServiceToProtocol(nrv.Protocol)
	if protocol == "" {
		return nil, fmt.Errorf("unsupported service %q on %s", nrv.Protocol, target)
	}

	logVerbose(base.verbose, "Nerva detected %s (TLS: %v) on %s", protocol, nrv.TLS, target)

	return &fingerprintedService{protocol: protocol, tls: nrv.TLS, noAuth: nrv.HasNoAuth()}, nil
}

// fingerprintTargets parses host:port strings into Nerva targets, fingerprints
// them, and returns the discovered services. This is the shared implementation
// for phases 1 & 2 of both runFromFingerprint and runLogonFingerprint.
func fingerprintTargets(targets []string, base *runConfig) (context.CancelFunc, []nervaplugins.Service, bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Phase 1: Parse host:port strings into Nerva targets.
	var nervaTargets []nervaplugins.Target
	for _, t := range targets {
		nt, err := brutusinput.ParseNervaTarget(ctx, t)
		if err != nil {
			warnMsg(base.useColor, "skipping %q: %v", t, err)
			continue
		}
		nervaTargets = append(nervaTargets, nt)
	}
	if len(nervaTargets) == 0 {
		errMsg(base.useColor, "no valid targets after parsing")
		stop()
		return nil, nil, false
	}

	// Phase 2: Fingerprint with Nerva.
	if !base.quiet {
		fmt.Fprintf(os.Stderr, "%s Fingerprinting %d target(s) with Nerva...\n",
			dim(base.useColor, SymbolInfo), len(nervaTargets))
	}

	services, err := scan.ScanTargets(ctx, nervaTargets, nervaScanConfig(base))
	if err != nil {
		errMsg(base.useColor, "fingerprinting failed: %v", err)
		stop()
		return nil, nil, false
	}

	logVerbose(base.verbose, "Nerva discovered %d service(s) from %d target(s)", len(services), len(nervaTargets))

	if len(services) == 0 {
		warnMsg(base.useColor, "Nerva could not fingerprint any of the %d target(s)", len(nervaTargets))
		stop()
		return nil, nil, false
	}

	return stop, services, true
}

// runFromFingerprint fingerprints the given host:port targets using Nerva's
// library API, maps discovered services to Brutus protocols, and runs
// credential testing against each. Targets that Nerva cannot fingerprint
// are silently skipped (with a verbose log). The per-target brute-force
// loop mirrors runFromStdin.
func runFromFingerprint(targets []string, base *runConfig, jsonOut bool) ([]brutus.Result, bool) {
	stop, services, ok := fingerprintTargets(targets, base)
	if !ok {
		return nil, false
	}
	defer stop()

	var allResults []brutus.Result
	hasSuccess := false

	for i := range services {
		nrv := brutusinput.ServiceToNervaResult(&services[i])

		// Determine protocol: use override if specified, otherwise map from Nerva.
		var protocol string
		if base.protocolOverride != "" {
			protocol = base.protocolOverride
		} else {
			protocol = brutusinput.MapServiceToProtocol(nrv.Protocol)
			if protocol == "" {
				logVerbose(base.verbose, "skipping %s:%d - unsupported service %q", nrv.IP, nrv.Port, nrv.Protocol)
				continue
			}
		}

		// Apply subcommand protocol filter
		if base.protocolFilter != nil && !base.protocolFilter(protocol) {
			logVerbose(base.verbose, "skipping %s:%d - protocol %q filtered by subcommand", nrv.IP, nrv.Port, protocol)
			continue
		}

		// Determine TLS mode for this specific target.
		targetTLSMode := detectTLS(base.tlsMode, nrv.TLS, base.verbose)

		target := nrv.TargetAddr()

		// Detect HTTP auth type for web subcommand (form-based → browser protocol).
		var aiCreds []brutus.Credential
		if base.web != nil && (protocol == "http" || protocol == "https") {
			protocol, aiCreds = web.RouteHTTP(target, protocol, base.timeout, base.tlsMode, base.llmConfig)
		}

		if !jsonOut && !base.quiet {
			printTargetInfo(target, protocol, base, aiCreds)
		}

		// If Nerva detected anonymous access, create a finding directly
		// and skip the redundant CheckUnauth probe in the worker pool.
		nervaNoAuth := nrv.HasNoAuth()
		var nervaFinding []brutus.Result
		if nervaNoAuth {
			logVerbose(base.verbose, "Nerva detected unauthenticated access on %s (%s)", target, protocol)
			nervaFinding = []brutus.Result{{
				Protocol: protocol,
				Target:   target,
				Username: "(unauthenticated)",
				Success:  true,
				Banner:   fmt.Sprintf("[CRITICAL] %s accessible without authentication (detected by Nerva fingerprinting)", protocol),
			}}
			allResults = append(allResults, nervaFinding...)
			hasSuccess = true
		}

		// Run brute force against this target.
		results, success := runSingleTarget(target, protocol, targetTLSMode, base, aiCreds, nervaNoAuth)
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}

		// Stream valid-only output for human mode.
		if !jsonOut {
			outputValidOnly(results, base.useColor)
			// Combine Nerva finding + brute force results for security findings output
			allFindings := make([]brutus.Result, 0, len(nervaFinding)+len(results))
			allFindings = append(allFindings, nervaFinding...)
			allFindings = append(allFindings, results...)
			emitSecurityFindings(allFindings, base.useColor)
		}
	}

	return allResults, hasSuccess
}
