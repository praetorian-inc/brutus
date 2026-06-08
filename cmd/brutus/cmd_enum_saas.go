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
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
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

Modes:
  DNS recon only:     brutus enum saas --domain example.com
  Enumerate emails:   brutus enum saas --domain example.com -e user@example.com
  Generate + enum:    brutus enum saas --domain example.com --generate --format flast`,
	Example: `  # DNS TXT recon — discover SaaS services
  brutus enum saas --domain praetorian.com

  # Enumerate specific emails against discovered services
  brutus enum saas --domain praetorian.com -e test@praetorian.com,admin@praetorian.com

  # Enumerate emails from file
  brutus enum saas --domain praetorian.com -E emails.txt

  # Generate emails and enumerate
  brutus enum saas --domain praetorian.com --generate --format flast

  # Enumerate against specific services only
  brutus enum saas -e user@example.com -s microsoft365,google

  # JSON output
  brutus enum saas --domain praetorian.com -e test@praetorian.com --json`,
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
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format for generation (first.last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.BoolVar(&flagSaasGenerate, "generate", false, "Generate emails from embedded name lists")
	f.StringVar(&flagSaasKnownValid, "known-valid", "", "Known-valid email to validate oracles before enumeration")
}

// registerDiscoverFlags registers flags for the discover subcommand.
func registerDiscoverFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to discover services from DNS TXT records")
	f.StringVarP(&flagSaasServices, "services", "s", "", "Comma-separated services to test (default: all registered)")
	f.StringVar(&flagSaasKnownValid, "known-valid", "", "Known-valid email to test against oracles (required)")
	_ = cmd.MarkFlagRequired("known-valid")
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
				outputDNSReconHuman(dnsResult, useColor)
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
			outputDNSReconJSONL(jsonWriter, dnsResult)
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

	// Phase 3.5: Oracle validation with known-valid email
	if flagSaasKnownValid != "" {
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
			outputDNSReconJSONL(jsonWriter, dnsResult)
		}
		outputEnumJSONL(jsonWriter, results)
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
	if flagSaasServices != "" {
		for _, s := range strings.Split(flagSaasServices, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				services = append(services, s)
			}
		}
	}

	// DNS recon (informational only — discover always tests all plugins)
	if flagEnumDomain != "" {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Querying DNS TXT records for %s...\n",
				dim(useColor, SymbolInfo), flagEnumDomain)
		}
		dnsResult := enum.LookupDomainTXT(ctx, flagEnumDomain)
		if dnsResult.Error != nil {
			warnMsg(useColor, "DNS lookup failed: %v", dnsResult.Error)
		} else if !flagJSON {
			outputDNSReconHuman(dnsResult, useColor)
		}
	}

	// Test all registered plugins unless --services explicitly specified
	if len(services) == 0 {
		services = enum.ListPlugins()
	}

	if len(services) == 0 {
		return fmt.Errorf("no enumeration plugins available")
	}

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
	results, err := enum.EnumerateWithContext(ctx, cfg)
	if err != nil {
		return fmt.Errorf("oracle testing failed: %w", err)
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
	} else {
		outputOracleValidationHuman(results, useColor)
	}

	return nil
}
