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

// Oracle-enumeration flag variables
var (
	flagOraclesEmails     string
	flagOraclesEmailFile  string
	flagOraclesServices   string
	flagOraclesGenerate   bool
	flagOraclesKnownValid string
)

var enumOraclesCmd = &cobra.Command{
	Use:   "oracles",
	Short: "Enumerate which account-existence oracles work for an organization",
	Long: `Identify which unauthenticated account-existence oracles (e.g. microsoft365,
google) — plus the Microsoft Teams oracle — work for an organization, validate
them against a known-valid user, then enumerate candidate emails against the
working oracles. The org domain defaults to the --known-valid email's domain, so
an explicit --domain is only needed to target a different domain.

DNS TXT recon surfaces the candidate oracles for the org; the validation step
(against --known-valid) is the headline: it reports, per oracle, whether the
oracle WORKED or NOT. --known-valid is required, and enumeration runs only
against the oracles that confirm it (including the Microsoft Teams oracle when
applicable).

Modes:
  Oracle check only:  brutus enum active oracles --known-valid admin@example.com
  Enumerate emails:   brutus enum active oracles -e user@example.com --known-valid admin@example.com
  Generate + enum:    brutus enum active oracles --generate --format flast --known-valid admin@example.com`,
	Example: `  # Discover candidate oracles via DNS and report which ones work
  # (domain defaults to the --known-valid email's domain)
  brutus enum active oracles --known-valid admin@praetorian.com

  # Enumerate specific emails against the working oracles
  brutus enum active oracles --domain praetorian.com -e test@praetorian.com,admin@praetorian.com --known-valid admin@praetorian.com

  # Enumerate emails from file
  brutus enum active oracles --domain praetorian.com -E emails.txt --known-valid admin@praetorian.com

  # Generate emails and enumerate against working oracles
  brutus enum active oracles --domain target.com --generate --format first.last --known-valid admin@target.com

  # Check / enumerate against specific oracles only
  brutus enum active oracles -e user@example.com -s microsoft365,google --known-valid admin@example.com

  # JSON output
  brutus enum active oracles --domain praetorian.com -e test@praetorian.com --known-valid admin@praetorian.com --json`,
	RunE: runEnumOracles,
}

var enumDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover working oracles by testing a known-valid email",
	Long: `Test a known-valid email against enumeration oracles to discover which
services have working account detection. Use this before large-scale enumeration
to avoid wasting time on broken or rate-limited oracles.

Optionally combine with --domain to auto-discover candidate oracles from DNS TXT records.`,
	Example: `  # Test oracles for a domain (auto-discovers candidate oracles from DNS)
  brutus enum active oracles discover --domain praetorian.com --known-valid admin@praetorian.com

  # Test specific oracles only
  brutus enum active oracles discover --known-valid admin@example.com -s microsoft365,google`,
	RunE: runEnumDiscover,
}

func init() {
	registerOraclesFlags(enumOraclesCmd)
	registerDiscoverFlags(enumDiscoverCmd)
	enumOraclesCmd.AddCommand(enumDiscoverCmd)
}

// registerOraclesFlags registers flags for the oracles subcommand.
func registerOraclesFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to enumerate for DNS recon and email generation (defaults to the --known-valid email's domain)")
	f.StringVarP(&flagOraclesEmails, "emails", "e", "", "Comma-separated emails to enumerate")
	f.StringVarP(&flagOraclesEmailFile, "email-file", "E", "", "File of emails to enumerate (one per line, use - for stdin)")
	f.StringVarP(&flagOraclesServices, "services", "s", "", "Comma-separated oracles to check (default: all discovered/registered)")
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format for generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.BoolVar(&flagOraclesGenerate, "generate", false, "Generate emails from embedded name lists")
	f.StringVar(&flagOraclesKnownValid, "known-valid", "", "Known-valid email to validate oracles before enumeration (required)")
	_ = cmd.MarkFlagRequired("known-valid")
}

// registerDiscoverFlags registers flags for the discover subcommand.
func registerDiscoverFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to discover candidate oracles from DNS TXT records")
	f.StringVarP(&flagOraclesServices, "services", "s", "", "Comma-separated oracles to test (default: all registered)")
	f.StringVar(&flagOraclesKnownValid, "known-valid", "", "Known-valid email to test against oracles (required)")
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

// domainIndependentOracles lists registered oracles that apply to any email
// regardless of the org's DNS/SaaS footprint, so DNS recon never surfaces them
// (GitHub account existence is checkable for any address; there is no per-tenant
// DNS TXT record to discover). They are unioned into the auto-discovered oracle
// set in runEnumOracles so the oracle check covers them.
var domainIndependentOracles = []string{"github"}

// addDomainIndependentOracles appends any registered domain-independent oracles
// (see domainIndependentOracles) to services that are not already present. It is
// used only in the DNS auto-discovery path; an explicit --services list is
// honored verbatim and never has oracles added to it. registeredSet is the set
// of currently-registered plugin names, so an oracle is added only when its
// plugin is actually registered.
func addDomainIndependentOracles(services []string, registeredSet map[string]bool) []string {
	present := make(map[string]bool, len(services))
	for _, s := range services {
		present[s] = true
	}
	for _, name := range domainIndependentOracles {
		if registeredSet[name] && !present[name] {
			services = append(services, name)
			present[name] = true
		}
	}
	return services
}

// runEnumOracles handles the main oracles enum command. Its output leads with
// the oracle check — which oracles were validated against --known-valid and
// whether each WORKED or NOT — and treats the DNS recon merely as a one-line
// explanation of why those oracles are candidates. Enumeration then runs only
// against the working oracles.
func runEnumOracles(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	// --domain defaults to the domain of the required --known-valid email, so
	// callers don't have to repeat a domain they already supplied in the
	// known-valid address (e.g. `--known-valid admin@example.com` is enough to
	// drive DNS recon and email generation for example.com). An explicit
	// --domain still wins.
	flagEnumDomain = resolveOraclesDomain(flagEnumDomain, flagOraclesKnownValid)

	if flagEnumDomain == "" && flagOraclesEmails == "" && flagOraclesEmailFile == "" {
		return fmt.Errorf("--domain, --emails/-e, or --email-file/-E is required (or pass a --known-valid address with a domain)")
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

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	// Phase 1: DNS TXT recon — supporting context, not the headline. Surfaces
	// the candidate oracles so the oracle check below has something to validate.
	// Full TXT detail stays under --verbose and in JSON; the human path leads
	// with a single "Discovered candidate oracles" line.
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
				outputCandidateOraclesHuman(dnsResult, teamsOracleAvailable(dnsResult), useColor)
				if flagVerbose {
					outputDNSReconHuman(dnsResult, teamsOracleAvailable(dnsResult), useColor)
				}
			}
		}
	}

	// Phase 2: Build email list
	var emails []string

	// From --emails flag
	if flagOraclesEmails != "" {
		for _, e := range strings.Split(flagOraclesEmails, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				emails = append(emails, e)
			}
		}
	}

	// From --email-file flag
	if flagOraclesEmailFile != "" {
		fileEmails, loadErr := loadLinesFromFile(flagOraclesEmailFile)
		if loadErr != nil {
			return fmt.Errorf("loading email file: %w", loadErr)
		}
		emails = append(emails, fileEmails...)
	}

	// From --generate flag
	if flagOraclesGenerate {
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

	// Determine the oracle-check label up front: the domain when provided,
	// otherwise the explicit targets, so the Oracle Check block can announce
	// what was checked even when there are no emails to enumerate.
	checkLabel := oracleCheckLabel(emails)

	// Phase 3: Determine oracles to check
	var services []string
	if flagOraclesServices != "" {
		for _, s := range strings.Split(flagOraclesServices, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				services = append(services, s)
			}
		}
	} else if len(discoveredServices) > 0 {
		// Filter to only oracles that have registered plugins
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
		// Domain-independent oracles (e.g. github) have no DNS TXT footprint, so
		// DNS recon never surfaces them — yet they apply to any corporate email
		// regardless of the org's SaaS tenancy. Union them in so the oracle check
		// covers them alongside the DNS-discovered tenant oracles. Only done in the
		// auto-discovery path; an explicit --services list is respected verbatim.
		services = addDomainIndependentOracles(services, registeredSet)
	}
	// If still empty, enum.Config.Services=nil means "all registered"

	// Phase 3.5: Oracle check against the known-valid email — THE HEADLINE.
	// --known-valid is a required flag, so this validation always runs before
	// enumeration. It reports, per oracle, whether the oracle WORKED or NOT, and
	// enumeration is restricted to the oracles that confirmed the known-valid
	// email.
	svcList := services
	if len(svcList) == 0 {
		svcList = enum.ListPlugins()
	}
	if len(svcList) > 0 {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Checking oracles against known-valid email %s...\n",
				dim(useColor, SymbolInfo), flagOraclesKnownValid)
		}

		validCfg := &enum.Config{
			Emails:   []string{flagOraclesKnownValid},
			Services: svcList,
			Threads:  flagThreads,
			Timeout:  flagTimeout,
			Verbose:  flagVerbose,
			ProxyURL: proxyURL,
		}
		validResults, validErr := enum.EnumerateWithContext(ctx, validCfg)
		if validErr != nil {
			warnMsg(useColor, "Oracle check error: %v", validErr)
		} else {
			// Opportunistically confirm the Teams oracle so it can be rendered as
			// part of the same Oracle Check block. Attempt only when the org looks
			// like M365 (microsoft365 discovered via DNS) or the user explicitly
			// asked for teams via --services. Reuses confirmTeamsOracle — no
			// duplicated token/enumerator logic.
			teamsLine := maybeConfirmTeamsOracle(ctx, dnsResult, useColor)

			if !flagJSON {
				outputOracleCheckHuman(checkLabel, flagOraclesKnownValid, validResults, teamsLine, useColor)
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

			// If there are no emails to enumerate, the oracle check IS the
			// output: emit the JSON results and return without enumerating.
			if len(emails) == 0 {
				if flagJSON {
					if dnsResult != nil {
						outputDNSReconJSONL(jsonWriter, dnsResult, teamsOracleAvailable(dnsResult))
					}
					outputEnumJSONL(jsonWriter, validResults)
					if teamsLine != "" {
						outputDiscoverTeamsJSONL(jsonWriter, teamsLine)
					}
				}
				return nil
			}

			// Carry the confirmed Teams line into the enumeration JSON output so
			// machine consumers see the same oracle-check result the human block
			// rendered.
			if flagJSON && teamsLine != "" {
				defer outputDiscoverTeamsJSONL(jsonWriter, teamsLine)
			}
		}
	}

	// If there were no oracles to check at all and no emails, there is nothing
	// left to do beyond the DNS recon already surfaced above.
	if len(emails) == 0 {
		if dnsResult != nil && flagJSON {
			outputDNSReconJSONL(jsonWriter, dnsResult, teamsOracleAvailable(dnsResult))
		}
		if dnsResult == nil {
			return fmt.Errorf("no emails to enumerate — provide --emails, --email-file, or --generate")
		}
		return nil
	}

	if !flagQuiet && !flagJSON {
		svcNames := services
		if len(svcNames) == 0 {
			svcNames = enum.ListPlugins()
		}
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against %d working oracle(s): %s\n",
			dim(useColor, SymbolInfo), len(emails), len(svcNames), strings.Join(svcNames, ", "))
	}

	// Phase 4: Run enumeration against the working oracles
	cfg := &enum.Config{
		Emails:    emails,
		Services:  services,
		Threads:   flagThreads,
		Timeout:   flagTimeout,
		RateLimit: flagRateLimit,
		Jitter:    flagJitter,
		Verbose:   flagVerbose,
		ProxyURL:  proxyURL,
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
	} else {
		outputEnumHuman(results, useColor)
	}

	return nil
}

// runEnumDiscover handles the "oracles discover" subcommand.
func runEnumDiscover(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	// Phase 1: Determine oracles to test
	var services []string
	teamsRequested := false
	if flagOraclesServices != "" {
		for _, s := range strings.Split(flagOraclesServices, ",") {
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
				dim(useColor, SymbolInfo), len(services), flagOraclesKnownValid)
		}

		// Phase 2: Test oracles
		cfg := &enum.Config{
			Emails:   []string{flagOraclesKnownValid},
			Services: services,
			Threads:  flagThreads,
			Timeout:  flagTimeout,
			Verbose:  flagVerbose,
			ProxyURL: proxyURL,
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
		teamsLine = confirmTeamsOracle(ctx, flagOraclesKnownValid, useColor)
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

// maybeConfirmTeamsOracle opportunistically confirms the Microsoft Teams oracle
// for the oracle-check block, mirroring runEnumDiscover. It attempts confirmation
// only when the org looks like M365 (microsoft365 discovered via DNS) or the user
// explicitly asked for teams via --services, and returns "" otherwise. Reuses
// confirmTeamsOracle — no duplicated token/enumerator logic.
func maybeConfirmTeamsOracle(ctx context.Context, dnsResult *enum.DNSReconResult, useColor bool) string {
	teamsRequested := false
	for _, s := range strings.Split(flagOraclesServices, ",") {
		if strings.TrimSpace(s) == "teams" {
			teamsRequested = true
			break
		}
	}
	if !teamsOracleAvailable(dnsResult) && !teamsRequested {
		return ""
	}
	return confirmTeamsOracle(ctx, flagOraclesKnownValid, useColor)
}

// confirmTeamsOracle opportunistically confirms the Microsoft Teams enumeration
// oracle against knownValid. It resolves a token from the cached credential
// store (teamsDefaultTokenPath / teamsEnumReadTokenFile) or an explicit
// --access-token already present on the oracles command, reusing the same teams
// enumerator and credstore helpers as "enum teams users" (no duplicated HTTP or
// token logic). When no token is available it reports teams as
// "available (unconfirmed)" and does nothing else (no error). The returned
// string is a single discover-style status line; token values never appear in
// it.
func confirmTeamsOracle(ctx context.Context, knownValid string, useColor bool) string {
	accessToken, refreshToken, ok := resolveTeamsConfirmToken(useColor)
	if !ok {
		return "teams: available (unconfirmed) — run `brutus enum active teams auth` then re-run to confirm"
	}

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return fmt.Sprintf("teams: proxy misconfigured: %v", err)
	}

	enumerator, err := teams.NewEnumerator(accessToken, refreshToken, proxyURL, flagTimeout, false)
	if err != nil {
		return fmt.Sprintf("teams: unconfirmed (enumerator setup failed: %v)", err)
	}

	// Wire a refresh callback only when a refresh token is available, mirroring
	// runEnumTeamsUsers so an expired access token is renewed once.
	if refreshToken != "" {
		client, cerr := teams.NewClient("organizations", teams.DefaultClientID, teams.DefaultScope, proxyURL, flagTimeout)
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
	return teamsDiscoverLine(&res)
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
func teamsDiscoverLine(res *teams.EnumResult) string {
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

// oracleCheckLabel returns the label for the Oracle Check header: the --domain
// when one was provided, otherwise a compact list of the explicit email targets.
func oracleCheckLabel(emails []string) string {
	if flagEnumDomain != "" {
		return flagEnumDomain
	}
	if len(emails) > 0 {
		return strings.Join(emails, ", ")
	}
	return "(no targets)"
}

// emailDomain returns the domain portion of an email address: the substring
// after the last "@". It returns "" when the value has no usable domain part
// (no "@", or "@" is the final character). Used so --domain can default to the
// domain of the required --known-valid email.
func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// resolveOraclesDomain returns the effective org domain for the oracles command.
// An explicit --domain always wins; otherwise it falls back to the domain of the
// required --known-valid email (see emailDomain). Returns "" when neither yields
// a domain. Kept as a pure function so the precedence (explicit over derived) is
// unit-testable without running runEnumOracles' network path.
func resolveOraclesDomain(domain, knownValid string) string {
	if domain != "" {
		return domain
	}
	return emailDomain(knownValid)
}
