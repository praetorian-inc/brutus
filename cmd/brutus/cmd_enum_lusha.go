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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum/lusha"
)

// File-local flag variables for the lusha subcommand.
// Separate from other enum commands to avoid cross-command state bleed.
var (
	flagLushaFirstName string
	flagLushaLastName  string
	flagLushaCompany   string
	flagLushaDomain    string
	flagLushaEmail     string
	flagLushaLinkedin  string
	flagLushaPhone     bool
	flagLushaEmailOnly bool
	flagLushaAPIKey    string
	flagLushaLimit     int
)

// newEnumLushaCmd builds the "lusha" command. A fresh instance is constructed
// per call so the same command can be mounted under two parents (the canonical
// "enum passive lusha" path and the hidden back-compat "enum lusha" alias)
// without sharing one *cobra.Command. All instances bind the same package-level
// flag vars, which is fine since only one runs per invocation.
func newEnumLushaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lusha",
		Short: "Enrich a single person identity to emails and phones via Lusha v3",
		Long: `Resolve one person identity to an enriched contact (emails and phone
numbers) via the Lusha v3 search-and-enrich API. Provide exactly one identity:
a name (--first-name + --last-name) with a --company or --domain, OR an --email,
OR a --linkedin URL. Standalone — does not feed the saas enumeration pipeline.

ROSTER MODE: provide ONLY --domain (no name/email/linkedin) to enumerate a whole
company roster via the Lusha prospecting API. Use --limit N to bound the roster
(and credit spend); --limit 0 (the default) collects all matches. Roster mode
consumes ~1 credit per contact searched and enriched.

Every invocation consumes Lusha credits (the command has no free tier). Phone
numbers may carry a Do-Not-Call (DNC) flag, which is always shown — do not
contact a DNC number. You are responsible for ensuring your use complies with
the provider's Terms of Service and that you have authorization to enumerate the
targeted individuals/organizations.

Requires a Lusha API key via the LUSHA_API_KEY environment variable
(or the --api-key flag).`,
		Example: `  # Enrich by name + company (key from LUSHA_API_KEY)
  brutus enum passive lusha --first-name Ada --last-name Lovelace --company Analytical

  # Enrich by name + company domain
  brutus enum passive lusha --first-name Ada --last-name Lovelace --domain example.com

  # Enrich by email
  brutus enum passive lusha --email ada@example.com

  # Enrich by LinkedIn URL, also request phone numbers
  brutus enum passive lusha --linkedin https://linkedin.com/in/ada --phone

  # Roster: enumerate an entire company by domain (collect all — consumes credits)
  brutus enum passive lusha --domain example.com

  # Roster: cap the roster (and credit spend) at 25 contacts
  brutus enum passive lusha --domain example.com --limit 25

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum passive lusha --email ada@example.com --api-key abc123`,
		RunE: runEnumLusha,
	}

	f := cmd.Flags()
	f.StringVar(&flagLushaFirstName, "first-name", "", "First name (with --last-name and --company or --domain)")
	f.StringVar(&flagLushaLastName, "last-name", "", "Last name (with --first-name)")
	f.StringVar(&flagLushaCompany, "company", "", "Company name (with the name pair)")
	f.StringVar(&flagLushaDomain, "domain", "", "Company domain (alternative to --company)")
	f.StringVar(&flagLushaEmail, "email", "", "Enrich by email address (mutually exclusive identity)")
	f.StringVar(&flagLushaLinkedin, "linkedin", "", "Enrich by LinkedIn profile URL (mutually exclusive identity)")
	f.BoolVar(&flagLushaPhone, "phone", false, "Request phone datapoints in addition to email")
	f.BoolVar(&flagLushaEmailOnly, "email-only", false, "Request only email datapoints (mutually exclusive with --phone)")
	f.StringVar(&flagLushaAPIKey, "api-key", "",
		"Lusha API key (overrides LUSHA_API_KEY; WARNING: visible in process list and shell history — prefer LUSHA_API_KEY)")
	f.IntVar(&flagLushaLimit, "limit", 0,
		"Roster mode (--domain only): max contacts to search + enrich; 0 = collect all (consumes ~1 credit/contact)")
	// No MarkFlagRequired — identity is validated in runEnumLusha.

	return cmd
}

// runEnumLusha implements the "enum lusha" subcommand.
func runEnumLusha(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if err := validateLushaIdentity(); err != nil {
		return err
	}

	apiKey, err := resolveLushaAPIKey(flagLushaAPIKey)
	if err != nil {
		return err
	}

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
	client, err := lusha.NewClient(apiKey, flagTimeout, proxyURL)
	if err != nil {
		return err
	}

	// Roster mode: enumerate a whole company by domain via the prospecting API.
	if isLushaRosterMode() {
		return runEnumLushaRoster(ctx, client, jsonWriter, useColor)
	}

	// Unconditional cost notice — Lusha enrichment always spends credits (P0-7).
	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s lusha enrichment consumes credits\n", dim(useColor, SymbolInfo))
	}

	query := lusha.ContactQuery{
		FirstName:     flagLushaFirstName,
		LastName:      flagLushaLastName,
		CompanyName:   flagLushaCompany,
		CompanyDomain: flagLushaDomain,
		Email:         flagLushaEmail,
		LinkedinURL:   flagLushaLinkedin,
	}
	reveal := lusha.RevealOptions{Email: true, Phone: flagLushaPhone}
	if flagLushaEmailOnly {
		reveal = lusha.RevealOptions{Email: true, Phone: false}
	}

	contact, err := client.Enrich(ctx, &query, reveal)
	if err != nil {
		return classifyLushaError(err)
	}

	// Verbose: log counts only — never the key (P0-1).
	logVerbose(flagVerbose, "Lusha returned %d emails and %d phones",
		len(contact.Emails), len(contact.Phones))

	if flagJSON {
		outputLushaJSONL(jsonWriter, contact)
	} else {
		outputLushaHuman(os.Stdout, contact, useColor)
	}
	return nil
}

// isLushaRosterMode reports whether the flags select domain-roster enumeration:
// ONLY --domain is set (no --first-name/--last-name/--company/--email/--linkedin).
// Pure function over the flag values — trivially testable.
func isLushaRosterMode() bool {
	return flagLushaDomain != "" &&
		flagLushaFirstName == "" && flagLushaLastName == "" &&
		flagLushaCompany == "" && flagLushaEmail == "" && flagLushaLinkedin == ""
}

// runEnumLushaRoster enumerates a company roster by domain and writes it out.
// The cost notice goes to stderr (CLI layer only — the library prints nothing).
func runEnumLushaRoster(ctx context.Context, client *lusha.Client, jsonWriter io.Writer, useColor bool) error {
	if !flagQuiet && !flagJSON {
		count := fmt.Sprintf("%d", flagLushaLimit)
		if flagLushaLimit <= 0 {
			count = "all"
		}
		fmt.Fprintf(os.Stderr, "%s lusha: enumerating %s — searching + enriching up to %s contacts (consumes credits)\n",
			dim(useColor, SymbolInfo), flagLushaDomain, count)
	}

	roster, err := client.SearchDomain(ctx, flagLushaDomain, flagLushaLimit)
	if err != nil {
		return classifyLushaError(err)
	}

	logVerbose(flagVerbose, "Lusha roster: %d contacts, %d credits charged",
		len(roster.Contacts), roster.CreditsCharged)

	if flagJSON {
		outputLushaDomainJSONL(jsonWriter, roster)
	} else {
		outputLushaDomainHuman(os.Stdout, roster, useColor)
	}
	return nil
}

// validateLushaIdentity enforces a valid identity selection. Roster mode (ONLY
// --domain set) is valid for whole-company enumeration. Otherwise exactly one
// single-contact identity group must be set:
// (1) name group: --first-name + --last-name + exactly one of (--company | --domain),
// (2) --email, or (3) --linkedin. --phone and --email-only are mutually exclusive.
// Pure function over the flag values — no network, trivially testable.
func validateLushaIdentity() error {
	if flagLushaLimit < 0 {
		return fmt.Errorf("--limit must be >= 0")
	}
	if flagLushaPhone && flagLushaEmailOnly {
		return fmt.Errorf("--phone and --email-only are mutually exclusive")
	}

	// Roster mode: only --domain set → valid whole-company enumeration. The
	// reveal flags (--phone/--email-only) have no effect on the prospecting API,
	// so reject them here rather than silently ignoring them.
	if isLushaRosterMode() {
		if flagLushaPhone {
			return fmt.Errorf("--phone is not valid in roster mode (--domain only); the prospecting API returns all available datapoints")
		}
		if flagLushaEmailOnly {
			return fmt.Errorf("--email-only is not valid in roster mode (--domain only); the prospecting API returns all available datapoints")
		}
		return nil
	}

	hasName := flagLushaFirstName != "" || flagLushaLastName != "" ||
		flagLushaCompany != "" || flagLushaDomain != ""
	hasEmail := flagLushaEmail != ""
	hasLinkedin := flagLushaLinkedin != ""

	groups := 0
	if hasName {
		groups++
	}
	if hasEmail {
		groups++
	}
	if hasLinkedin {
		groups++
	}

	if groups == 0 {
		return fmt.Errorf("an identity is required: provide --first-name + --last-name + (--company or --domain), or --email, or --linkedin")
	}
	if groups > 1 {
		return fmt.Errorf("provide exactly one identity: use a name group, OR --email, OR --linkedin (not more than one)")
	}

	if !hasName {
		return nil
	}

	if flagLushaFirstName == "" || flagLushaLastName == "" {
		return fmt.Errorf("the name identity requires both --first-name and --last-name")
	}
	if flagLushaCompany == "" && flagLushaDomain == "" {
		return fmt.Errorf("the name identity requires --company or --domain")
	}
	if flagLushaCompany != "" && flagLushaDomain != "" {
		return fmt.Errorf("provide either --company or --domain for the name identity, not both")
	}
	return nil
}

// resolveLushaAPIKey returns the flag value if set, else LUSHA_API_KEY env var.
// The key is never logged (P0-1 security requirement).
func resolveLushaAPIKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if key := os.Getenv("LUSHA_API_KEY"); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("lusha API key required: set LUSHA_API_KEY or pass --api-key")
}

// classifyLushaError converts lusha sentinel errors into actionable, key-free
// messages. For *APIError it returns only status-derived text and never echoes
// the vendor's APIError.Details (which could carry the key) (P0-1). For non-API
// errors (network/DNS/timeout — no vendor details) it %w-wraps the cause to
// preserve debuggability.
func classifyLushaError(err error) error {
	switch {
	case errors.Is(err, lusha.ErrUnauthorized):
		return fmt.Errorf("lusha: invalid or missing API key (check LUSHA_API_KEY / --api-key)")
	case errors.Is(err, lusha.ErrNoCredits):
		return fmt.Errorf("lusha: insufficient credits — top up your Lusha account")
	case errors.Is(err, lusha.ErrForbidden):
		return fmt.Errorf("lusha: access forbidden (plan or permissions)")
	case errors.Is(err, lusha.ErrNotFound):
		return fmt.Errorf("lusha: no contact found for the provided identity")
	case errors.Is(err, lusha.ErrRateLimited):
		return fmt.Errorf("lusha: rate limit exceeded — wait and retry")
	}
	// Unknown error. If it carries an *APIError, report only its status code —
	// never its Details (P0-1); APIError.Error() is now status-only, but we keep
	// the explicit status-code text here regardless. Otherwise (network/DNS/
	// timeout — no vendor details) %w-wrap it to preserve debuggability, matching
	// classifyHunterError.
	var apiErr *lusha.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("lusha enrichment failed (HTTP %d)", apiErr.StatusCode)
	}
	return fmt.Errorf("lusha enrichment failed: %w", err)
}
