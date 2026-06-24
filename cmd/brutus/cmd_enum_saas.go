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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// SaaS-specific flag variables
var (
	flagSaasEmails     string
	flagSaasEmailFile  string
	flagSaasServices   string
	flagSaasGenerate   bool
	flagSaasKnownValid string
)

var enumSaasCmd = &cobra.Command{
	Use:   "saas",
	Short: "Enumerate email accounts against SaaS services",
	Long: `Discover SaaS services via DNS TXT records and enumerate email accounts
against discovered or specified services using unauthenticated oracles.

This command ALWAYS validates oracles against a known-valid user before
enumerating: --known-valid is required, and enumeration runs only against the
oracles that confirm it (including the Microsoft Teams oracle when applicable).

Modes:
  DNS recon only:     brutus enum saas --domain example.com --known-valid admin@example.com
  Enumerate emails:   brutus enum saas --domain example.com -e user@example.com --known-valid admin@example.com
  Generate + enum:    brutus enum saas --domain example.com --generate --format flast --known-valid admin@example.com`,
	Example: `  # DNS TXT recon — discover SaaS services (oracles validated against --known-valid)
  brutus enum saas --domain praetorian.com --known-valid admin@praetorian.com

  # Enumerate specific emails against validated services
  brutus enum saas --domain praetorian.com -e test@praetorian.com,admin@praetorian.com --known-valid admin@praetorian.com

  # Enumerate emails from file
  brutus enum saas --domain praetorian.com -E emails.txt --known-valid admin@praetorian.com

  # Generate emails and enumerate
  brutus enum saas --domain target.com --generate --format first.last --known-valid admin@target.com

  # Enumerate against specific services only
  brutus enum saas -e user@example.com -s microsoft365,google --known-valid admin@example.com

  # JSON output
  brutus enum saas --domain praetorian.com -e test@praetorian.com --known-valid admin@praetorian.com --json`,
	RunE: runEnumSaas,
}

var enumDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover working oracles by testing a known-valid email",
	Long: `Test a known-valid email against enumeration oracles to discover which
services have working account detection. Use this before large-scale enumeration
to avoid wasting time on broken or rate-limited oracles.

Optionally combine with --domain to auto-discover services from DNS TXT records.`,
	Example: `  # Test oracles for a domain (auto-discovers services from DNS)
  brutus enum saas discover --domain praetorian.com --known-valid admin@praetorian.com

  # Test specific services only
  brutus enum saas discover --known-valid admin@example.com -s microsoft365,google`,
	RunE: runEnumDiscover,
}

func init() {
	registerSaasFlags(enumSaasCmd)
	registerDiscoverFlags(enumDiscoverCmd)
	enumSaasCmd.AddCommand(enumDiscoverCmd)
}

// registerSaasFlags registers flags for the saas subcommand.
func registerSaasFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to enumerate (used for DNS recon and email generation)")
	f.StringVarP(&flagSaasEmails, "emails", "e", "", "Comma-separated emails to enumerate")
	f.StringVarP(&flagSaasEmailFile, "email-file", "E", "", "File of emails to enumerate (one per line, use - for stdin)")
	f.StringVarP(&flagSaasServices, "services", "s", "", "Comma-separated services to check (default: all discovered/registered)")
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format for generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.BoolVar(&flagSaasGenerate, "generate", false, "Generate emails from embedded name lists")
	f.StringVar(&flagSaasKnownValid, "known-valid", "", "Known-valid email to validate oracles before enumeration (required)")
	_ = cmd.MarkFlagRequired("known-valid")
}

// registerDiscoverFlags registers flags for the discover subcommand.
func registerDiscoverFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to discover services from DNS TXT records")
	f.StringVarP(&flagSaasServices, "services", "s", "", "Comma-separated services to test (default: all registered)")
	f.StringVar(&flagSaasKnownValid, "known-valid", "", "Known-valid email to test against oracles (required)")
	_ = cmd.MarkFlagRequired("known-valid")
}

// teamsOracleAvailable reports whether the Microsoft Teams enumeration oracle is
// applicable for the org behind result: it is whenever DNS recon detected a
// "microsoft365" service (the org is a Microsoft 365 tenant). This is inference
// only — teams is never injected into the DNS-parsing module (pkg/enum/dns.go
// stays a pure DNS parser) and is never added to the unauthenticated
// enumeration set (it is not a registered enum.Plugin).
func teamsOracleAvailable(result *enum.DNSReconResult) bool {
	if result == nil {
		return false
	}
	for i := range result.Services {
		if result.Services[i].Name == "microsoft365" {
			return true
		}
	}
	return false
}

// runEnumSaas handles the main saas enum command.
func runEnumSaas(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if flagEnumDomain == "" && flagSaasEmails == "" && flagSaasEmailFile == "" {
		return fmt.Errorf("--domain, --emails/-e, or --email-file/-E is required")
	}

	// Setup output writer
	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Phase 1: DNS TXT recon
	var dnsResult *enum.DNSReconResult
	var discoveredServices []string

	if flagEnumDomain != "" {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Querying DNS TXT records for %s...\n",
				dim(useColor, SymbolInfo), flagEnumDomain)
		}

		dnsResult = enum.LookupDomainTXT(ctx, flagEnumDomain)
		if dnsResult.Error != nil {
			warnMsg(useColor, "DNS lookup failed: %v", dnsResult.Error)
		} else {
			for _, svc := range dnsResult.Services {
				discoveredServices = append(discoveredServices, svc.Name)
			}

			if !flagJSON {
				outputDNSReconHuman(dnsResult, teamsOracleAvailable(dnsResult), useColor)
			}
		}
	}

	// Phase 2: Build email list
	var emails []string

	// From --emails flag
	if flagSaasEmails != "" {
		for _, e := range strings.Split(flagSaasEmails, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				emails = append(emails, e)
			}
		}
	}

	// From --email-file flag
	if flagSaasEmailFile != "" {
		fileEmails, loadErr := loadLinesFromFile(flagSaasEmailFile)
		if loadErr != nil {
			return fmt.Errorf("loading email file: %w", loadErr)
		}
		emails = append(emails, fileEmails...)
	}

	// From --generate flag
	if flagSaasGenerate {
		if flagEnumDomain == "" {
			return fmt.Errorf("--generate requires --domain")
		}
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Generating emails with format %q for %s...\n",
				dim(useColor, SymbolInfo), flagEnumFormat, flagEnumDomain)
		}
		generated, genErr := enum.GenerateEmails(flagEnumFormat, flagEnumDomain)
		if genErr != nil {
			return fmt.Errorf("generating emails: %w", genErr)
		}
		logVerbose(flagVerbose, "Generated %d emails", len(generated))
		emails = append(emails, generated...)
	}

	// If no emails to enumerate, just show DNS recon results
	if len(emails) == 0 {
		if dnsResult != nil && flagJSON {
			outputDNSReconJSONL(jsonWriter, dnsResult, teamsOracleAvailable(dnsResult))
		}
		if dnsResult == nil {
			return fmt.Errorf("no emails to enumerate — provide --emails, --email-file, or --generate")
		}
		return nil
	}

	// Phase 3: Determine services to check
	var services []string
	if flagSaasServices != "" {
		for _, s := range strings.Split(flagSaasServices, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				services = append(services, s)
			}
		}
	} else if len(discoveredServices) > 0 {
		// Filter to only services that have registered plugins
		registered := enum.ListPlugins()
		registeredSet := make(map[string]bool, len(registered))
		for _, r := range registered {
			registeredSet[r] = true
		}
		for _, s := range discoveredServices {
			if registeredSet[s] {
				services = append(services, s)
			}
		}
	}
	// If still empty, enum.Config.Services=nil means "all registered"

	// Phase 3.5: Oracle validation with known-valid email. --known-valid is a
	// required flag, so this validation always runs before enumeration, mirroring
	// the "discover" subcommand. Enumeration is restricted to the oracles that
	// confirmed the known-valid email.
	svcList := services
	if len(svcList) == 0 {
		svcList = enum.ListPlugins()
	}
	if len(svcList) > 0 {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Validating oracles with known-valid email %s...\n",
				dim(useColor, SymbolInfo), flagSaasKnownValid)
		}

		validCfg := &enum.Config{
			Emails:   []string{flagSaasKnownValid},
			Services: svcList,
			Threads:  flagThreads,
			Timeout:  flagTimeout,
			Verbose:  flagVerbose,
		}
		validResults, validErr := enum.EnumerateWithContext(ctx, validCfg)
		if validErr != nil {
			warnMsg(useColor, "Oracle validation error: %v", validErr)
		} else {
			if !flagJSON {
				outputOracleValidationHuman(validResults, useColor)
			}

			var validatedServices []string
			for _, r := range validResults {
				if r.Exists {
					validatedServices = append(validatedServices, r.Service)
				}
			}

			if len(validatedServices) == 0 {
				warnMsg(useColor, "No oracles confirmed the known-valid email — results may be unreliable")
			} else {
				services = validatedServices
			}
		}
	}

	// Phase 3.6: Opportunistically confirm the Teams oracle, mirroring
	// runEnumDiscover. Attempt only when the org looks like M365 (microsoft365
	// discovered via DNS) or the user explicitly asked for teams via --services.
	// Reuses confirmTeamsOracle — no duplicated token/enumerator logic.
	teamsRequested := false
	for _, s := range strings.Split(flagSaasServices, ",") {
		if strings.TrimSpace(s) == "teams" {
			teamsRequested = true
			break
		}
	}
	teamsLine := ""
	if teamsOracleAvailable(dnsResult) || teamsRequested {
		teamsLine = confirmTeamsOracle(ctx, flagSaasKnownValid, useColor)
		if !flagJSON && teamsLine != "" {
			fmt.Printf("  %s\n\n", teamsLine)
		}
	}

	if !flagQuiet && !flagJSON {
		svcNames := services
		if len(svcNames) == 0 {
			svcNames = enum.ListPlugins()
		}
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against %d service(s): %s\n",
			dim(useColor, SymbolInfo), len(emails), len(svcNames), strings.Join(svcNames, ", "))
	}

	// Phase 4: Run enumeration
	cfg := &enum.Config{
		Emails:    emails,
		Services:  services,
		Threads:   flagThreads,
		Timeout:   flagTimeout,
		RateLimit: flagRateLimit,
		Jitter:    flagJitter,
		Verbose:   flagVerbose,
	}

	results, err := enum.EnumerateWithContext(ctx, cfg)
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	// Phase 5: Output results
	if flagJSON {
		if dnsResult != nil {
			outputDNSReconJSONL(jsonWriter, dnsResult, teamsOracleAvailable(dnsResult))
		}
		outputEnumJSONL(jsonWriter, results)
		if teamsLine != "" {
			outputDiscoverTeamsJSONL(jsonWriter, teamsLine)
		}
	} else {
		outputEnumHuman(results, useColor)
	}

	return nil
}

// runEnumDiscover handles the "saas discover" subcommand.
func runEnumDiscover(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Phase 1: Determine services to test
	var services []string
	teamsRequested := false
	if flagSaasServices != "" {
		for _, s := range strings.Split(flagSaasServices, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				if s == "teams" {
					// teams is not a registered enum.Plugin; it is confirmed
					// opportunistically below, never via the plugin loop.
					teamsRequested = true
					continue
				}
				services = append(services, s)
			}
		}
	}

	// DNS recon (informational only — discover always tests all plugins). The
	// result is retained so the inferred Teams oracle can be surfaced and
	// opportunistically confirmed after the plugin oracles are tested.
	var dnsResult *enum.DNSReconResult
	if flagEnumDomain != "" {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Querying DNS TXT records for %s...\n",
				dim(useColor, SymbolInfo), flagEnumDomain)
		}
		dnsResult = enum.LookupDomainTXT(ctx, flagEnumDomain)
		if dnsResult.Error != nil {
			warnMsg(useColor, "DNS lookup failed: %v", dnsResult.Error)
		} else if !flagJSON {
			outputDNSReconHuman(dnsResult, teamsOracleAvailable(dnsResult), useColor)
		}
	}

	teamsAvailable := teamsOracleAvailable(dnsResult)

	// Test all registered plugins unless --services explicitly specified.
	// teams is never a registered plugin, so it is excluded from this set and
	// confirmed only via the opportunistic, token-gated path below.
	if len(services) == 0 && !teamsRequested {
		services = enum.ListPlugins()
	}

	if len(services) == 0 && !teamsAvailable && !teamsRequested {
		return fmt.Errorf("no enumeration plugins available")
	}

	var results []enum.Result
	if len(services) > 0 {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Testing %d oracle(s) with known-valid email %s...\n",
				dim(useColor, SymbolInfo), len(services), flagSaasKnownValid)
		}

		// Phase 2: Test oracles
		cfg := &enum.Config{
			Emails:   []string{flagSaasKnownValid},
			Services: services,
			Threads:  flagThreads,
			Timeout:  flagTimeout,
			Verbose:  flagVerbose,
		}
		var enumErr error
		results, enumErr = enum.EnumerateWithContext(ctx, cfg)
		if enumErr != nil {
			return fmt.Errorf("oracle testing failed: %w", enumErr)
		}
	}

	// Phase 2.5: Opportunistically confirm the Teams oracle. Attempt only when
	// the org looks like M365 (microsoft365 discovered) or the user explicitly
	// asked for teams via -s. Resolution and printing handle the no-token case
	// gracefully (no error). teams is never run through the unauthenticated
	// enumeration loop above.
	teamsLine := ""
	if teamsAvailable || teamsRequested {
		teamsLine = confirmTeamsOracle(ctx, flagSaasKnownValid, useColor)
	}

	// Phase 3: Output results
	if flagJSON {
		jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
		if err != nil {
			return err
		}
		defer closeOutput()
		_ = forceJSON
		outputEnumJSONL(jsonWriter, results)
		if teamsLine != "" {
			outputDiscoverTeamsJSONL(jsonWriter, teamsLine)
		}
	} else {
		outputOracleValidationHuman(results, useColor)
		if teamsLine != "" {
			fmt.Printf("  %s\n\n", teamsLine)
		}
	}

	return nil
}

// confirmTeamsOracle opportunistically confirms the Microsoft Teams enumeration
// oracle against knownValid. It resolves a token from the cached credential
// store (teamsDefaultTokenPath / teamsEnumReadTokenFile) or an explicit
// --access-token already present on the saas command, reusing the same teams
// enumerator and credstore helpers as "enum teams users" (no duplicated HTTP or
// token logic). When no token is available it reports teams as
// "available (unconfirmed)" and does nothing else (no error). The returned
// string is a single discover-style status line; token values never appear in
// it.
func confirmTeamsOracle(ctx context.Context, knownValid string, useColor bool) string {
	accessToken, refreshToken, ok := resolveTeamsConfirmToken(useColor)
	if !ok {
		return "teams: available (unconfirmed) — run `brutus enum teams auth` then re-run to confirm"
	}

	enumerator, err := teams.NewEnumerator(accessToken, refreshToken, flagProxy, flagTimeout, false)
	if err != nil {
		return fmt.Sprintf("teams: unconfirmed (enumerator setup failed: %v)", err)
	}

	// Wire a refresh callback only when a refresh token is available, mirroring
	// runEnumTeamsUsers so an expired access token is renewed once.
	if refreshToken != "" {
		client, cerr := teams.NewClient("organizations", teams.DefaultClientID, teams.DefaultScope, flagProxy, flagTimeout)
		if cerr == nil {
			enumerator.SetRefreshFunc(func(ctx context.Context) (string, error) {
				tok, rerr := client.RefreshAccessToken(ctx, refreshToken)
				if rerr != nil {
					return "", rerr
				}
				return tok.AccessToken, nil
			})
		}
	}

	res := enumerator.EnumerateOne(ctx, knownValid)
	return teamsDiscoverLine(res)
}

// resolveTeamsConfirmToken resolves a Teams token opportunistically for the
// discover confirmation path from the cached credential store
// (~/.brutus/teams.json) via teamsEnumReadTokenFile — reusing the same store
// "enum teams auth" writes, so no new flags are introduced. It returns ok=false
// (and never an error) when no token is available, so the caller degrades to an
// "available (unconfirmed)" report. Token values are never logged.
func resolveTeamsConfirmToken(useColor bool) (accessToken, refreshToken string, ok bool) {
	path, err := teamsDefaultTokenPath()
	if err != nil {
		return "", "", false
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return "", "", false
	}

	at, rt, readErr := teamsEnumReadTokenFile(path)
	if readErr != nil {
		return "", "", false
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Using saved Teams tokens from %s to confirm the teams oracle\n",
			dim(useColor, SymbolInfo), path)
	}
	return at, rt, true
}

// teamsDiscoverLine maps a Teams enumeration result to a discover-style status
// line. A 403/blocked result is still a working oracle (it distinguishes real
// from fake accounts). Token values never appear in the returned string.
func teamsDiscoverLine(res teams.EnumResult) string {
	switch res.Exists {
	case teams.ExistenceYes:
		line := "teams: working (corporate account resolved)"
		if t := teams.AccountType(res.MRI); t != "" {
			line += " [" + t + "]"
		}
		return line
	case teams.ExistenceBlocked:
		return "teams: working (account exists; external detail restricted)"
	case teams.ExistenceNo:
		return "teams: responded, known-valid not found (check the seed email / consumer-only)"
	default:
		return "teams: unconfirmed (auth/transport error)"
	}
}

// outputDiscoverTeamsJSONL emits the Teams discover confirmation as a single
// JSONL object alongside the other discover oracle results. Only the
// human-readable status line is carried — no token values.
func outputDiscoverTeamsJSONL(w io.Writer, statusLine string) {
	type discoverTeamsJSON struct {
		Type    string `json:"type"`
		Service string `json:"service"`
		Result  string `json:"result"`
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(discoverTeamsJSON{
		Type:    "discover_teams",
		Service: "teams",
		Result:  statusLine,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding discover teams JSON: %v\n", err)
	}
}
