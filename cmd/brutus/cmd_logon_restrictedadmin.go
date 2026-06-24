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
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// Restricted Admin login flags. The web/open flags reuse the shared logon flag
// vars (flagWeb/flagOpen). Credential flags are feature-local to keep the
// Restricted Admin command self-contained.
var (
	flagRAUsername string
	flagRAPassword string
	flagRAHash     string
	flagRADomain   string
)

// restrictedAdminCmd scans RDP hosts for Restricted Admin Mode support and, with
// --web, opens an authenticated pass-the-hash session in the built-in browser
// terminal.
var restrictedAdminCmd = &cobra.Command{
	Use:     "restrictedadmin",
	Aliases: []string{"restricted-admin", "ram"},
	Short:   "Scan RDP hosts for Restricted Admin Mode; log in via pass-the-hash",
	Long: `Scan RDP hosts for "Restricted Admin Mode" support and, optionally, log in.

Scan mode (default):
  An unauthenticated RDP security-negotiation probe that asks each host whether it
  advertises RESTRICTED_ADMIN_MODE_SUPPORTED. No credentials are sent and no WASM
  is touched, so it is fast and safe for mass scanning. The protocol defaults to
  RDP.

Login mode (--web):
  With --username and one of --password or --hash, opens an authenticated
  Restricted Admin session in the built-in browser terminal. Supplying --hash
  performs a pass-the-hash login. Login requires the target server to have
  Restricted Admin Mode enabled.`,
	Example: `  # Scan a single host for Restricted Admin Mode support
  brutus logon restrictedadmin --target 10.0.0.50:3389

  # Scan a list of targets from a file
  brutus logon restrictedadmin --targets-file targets.txt

  # Scan targets piped on stdin (only RDP targets are probed)
  echo "10.0.0.50:3389" | brutus logon restrictedadmin

  # Pass-the-hash login via the built-in browser terminal
  brutus logon restrictedadmin --web --open --target 10.0.0.50:3389 \
    --username CORP\\Administrator --hash aad3b435b51404eeaad3b435b51404ee`,
	RunE: runRestrictedAdmin,
}

func init() {
	registerRestrictedAdminFlags(restrictedAdminCmd)
	logonCmd.AddCommand(restrictedAdminCmd)
}

// registerRestrictedAdminFlags binds the Restricted Admin login flags. It uses no
// short flags to avoid collisions with the persistent -t/-o/-q/-v/-m flags and the
// -u/-p credential shorts used by other subcommands. Target/output/performance
// flags are persistent flags already registered on rootCmd and are read via their
// existing global vars and buildBaseConfig.
func registerRestrictedAdminFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&flagRAUsername, "username", "", "Username for login (DOMAIN\\user or user@domain)")
	f.StringVar(&flagRAPassword, "password", "", "Password for login (mutually exclusive with --hash)")
	f.StringVar(&flagRAHash, "hash", "", "NT hash for pass-the-hash login (mutually exclusive with --password)")
	f.StringVar(&flagRADomain, "domain", "", "Domain for login when username is a bare name")
	f.BoolVar(&flagWeb, "web", false, "Open an authenticated browser session (requires --target and credentials)")
	f.BoolVar(&flagOpen, "open", false, "Auto-open the browser when the web terminal starts")
}

// runRestrictedAdmin dispatches to the scan or web-login path based on flags.
func runRestrictedAdmin(cmd *cobra.Command, args []string) error {
	base := buildBaseConfig(cmd)
	if base.protocolOverride == "" {
		base.protocolOverride = "rdp"
	}

	if flagWeb {
		return runRestrictedAdminWeb(base)
	}
	if flagOpen && !flagWeb {
		return fmt.Errorf("--open requires --web")
	}
	return runRestrictedAdminScan(base)
}

// runRestrictedAdminScan probes the selected targets for Restricted Admin Mode
// support concurrently and renders the results. A completed scan is a success
// regardless of findings.
func runRestrictedAdminScan(base *baseConfigOptions) error {
	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	useStdin := detectStdinMode(flagTarget, flagTargetsFile)
	if err := validateTargetSources(useStdin); err != nil {
		return err
	}

	targets, err := collectRestrictedAdminTargets(base, useStdin)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no RDP targets to scan")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	threads := base.threads
	if threads < 1 {
		threads = 1
	}

	results := make([]*logon.RestrictedAdminResult, len(targets))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)
	for i := range targets {
		idx, target := i, targets[i]
		g.Go(func() error {
			if ctx.Err() != nil {
				results[idx] = &logon.RestrictedAdminResult{
					Target:  target,
					Verdict: logon.VerdictUnknown,
					Detail:  "cancelled",
				}
				return nil
			}
			results[idx] = logon.ScanRestrictedAdmin(ctx, target, base.timeout, base.proxyURL)
			return nil
		})
	}
	_ = g.Wait()

	if flagJSON {
		outputRestrictedAdminJSONL(jsonWriter, results)
	} else {
		outputRestrictedAdminHuman(results, base.useColor)
	}
	return nil
}

// runRestrictedAdminWeb opens an authenticated (password or pass-the-hash)
// Restricted Admin session in the built-in browser terminal.
func runRestrictedAdminWeb(base *baseConfigOptions) error {
	if flagTarget == "" {
		return fmt.Errorf("--web requires --target")
	}

	creds := logon.AuthCredentials{
		Username: flagRAUsername,
		Domain:   flagRADomain,
		Password: flagRAPassword,
	}
	if flagRAHash != "" {
		h, err := logon.NormalizeNTHash(flagRAHash)
		if err != nil {
			return err
		}
		creds.NTHash = h
	}
	if err := creds.Validate(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, ok := logon.RunRestrictedAdminWeb(ctx, logon.RestrictedAdminWebConfig{
		Target:      flagTarget,
		Timeout:     base.timeout,
		OpenBrowser: flagOpen,
		Creds:       creds,
	})
	if !ok {
		return fmt.Errorf("restricted admin web session: %w", result.Error)
	}
	return nil
}

// collectRestrictedAdminTargets gathers the RDP targets to scan from the active
// target source (stdin, nmap/masscan/targets file, or --target). Non-RDP entries
// from typed sources are skipped.
func collectRestrictedAdminTargets(base *baseConfigOptions, useStdin bool) ([]string, error) {
	switch {
	case useStdin:
		return collectRestrictedAdminStdinTargets(base), nil
	case flagNmapFile != "":
		entries, err := brutusinput.LoadNmapFile(flagNmapFile)
		if err != nil {
			return nil, err
		}
		var targets []string
		for i := range entries {
			nrv := &entries[i]
			if nrv.Protocol == "" || nrv.Protocol == "rdp" {
				targets = append(targets, nrv.TargetAddr())
			}
		}
		return targets, nil
	case flagMasscanFile != "":
		entries, err := brutusinput.LoadMasscanFile(flagMasscanFile)
		if err != nil {
			return nil, err
		}
		var targets []string
		for i := range entries {
			targets = append(targets, entries[i].TargetAddr())
		}
		return targets, nil
	case flagTargetsFile != "":
		return brutusinput.LoadTargetsFromFile(flagTargetsFile)
	default:
		if flagTarget == "" {
			return nil, fmt.Errorf("--target is required (or use --targets-file/--nmap-file/--masscan-file or pipe targets to stdin)")
		}
		return []string{flagTarget}, nil
	}
}

// collectRestrictedAdminStdinTargets reads targets from stdin, keeping only RDP
// (or protocol-less) entries. Malformed lines are warned about and skipped.
func collectRestrictedAdminStdinTargets(base *baseConfigOptions) []string {
	var targets []string
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
		case brutusinput.StdinLineHostPort:
			targets = append(targets, parsed.Raw)
		case brutusinput.StdinLineURI:
			if parsed.Protocol == "" || parsed.Protocol == "rdp" {
				targets = append(targets, parsed.HostPort)
			}
		case brutusinput.StdinLineJSON:
			proto := brutusinput.MapServiceToProtocol(parsed.NervaResult.Protocol)
			if proto == "" || proto == "rdp" {
				targets = append(targets, parsed.NervaResult.TargetAddr())
			}
		}
	}
	return targets
}

// =============================================================================
// OUTPUT HELPERS
// =============================================================================

// outputRestrictedAdminHuman renders the scan results in human-readable form with
// a per-host line and a footer summary.
func outputRestrictedAdminHuman(results []*logon.RestrictedAdminResult, useColor bool) {
	fmt.Printf("\n%s\n", heading(useColor, "RDP Restricted Admin Mode scan"))

	var supported, notSupported, unknown, unreachable int
	for _, r := range results {
		if r == nil {
			continue
		}

		label, color := restrictedAdminLabel(r)
		switch {
		case !r.Reachable:
			unreachable++
		case r.Verdict == logon.VerdictSupported:
			supported++
		case r.Verdict == logon.VerdictNotSupported:
			notSupported++
		default:
			unknown++
		}

		line := fmt.Sprintf("  %s%-12s%s %s", colorIf(useColor, color), label, colorIf(useColor, ColorReset), r.Target)
		if r.NegotiationReceived {
			line += fmt.Sprintf("  %s", logon.ProtocolName(r.SelectedProtocol))
		}
		if r.Detail != "" {
			line += fmt.Sprintf("  %s", dim(useColor, r.Detail))
		}
		fmt.Println(line)
	}

	total := supported + notSupported + unknown + unreachable
	fmt.Printf("\n%s %d supported, %d not-supported, %d unknown, %d unreachable (of %d hosts)\n",
		dim(useColor, SymbolInfo), supported, notSupported, unknown, unreachable, total)
}

// restrictedAdminLabel returns the display label and ANSI color for a result.
func restrictedAdminLabel(r *logon.RestrictedAdminResult) (label, color string) {
	switch {
	case !r.Reachable:
		return "UNREACHABLE", ColorRed
	case r.Verdict == logon.VerdictSupported:
		return "SUPPORTED", ColorGreen
	case r.Verdict == logon.VerdictNotSupported:
		return "not supported", ColorDim
	default:
		return "unknown", ColorYellow
	}
}

// outputRestrictedAdminJSONL writes one JSON object per line for pipeline consumption.
func outputRestrictedAdminJSONL(w io.Writer, results []*logon.RestrictedAdminResult) {
	enc := json.NewEncoder(w)
	for _, r := range results {
		if r == nil {
			continue
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding restricted admin JSON: %v\n", err)
		}
	}
}
