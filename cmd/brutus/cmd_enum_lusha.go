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
)

var enumLushaCmd = &cobra.Command{
	Use:   "lusha",
	Short: "Enrich a single person identity to emails and phones via Lusha v3",
	Long: `Resolve one person identity to an enriched contact (emails and phone
numbers) via the Lusha v3 search-and-enrich API. Provide exactly one identity:
a name (--first-name + --last-name) with a --company or --domain, OR an --email,
OR a --linkedin URL. Standalone — does not feed the saas enumeration pipeline.

Every invocation consumes Lusha credits (the command has no free tier). Phone
numbers may carry a Do-Not-Call (DNC) flag, which is always shown — do not
contact a DNC number. You are responsible for ensuring your use complies with
the provider's Terms of Service and that you have authorization to enumerate the
targeted individuals/organizations.

Requires a Lusha API key via the LUSHA_API_KEY environment variable
(or the --api-key flag).`,
	Example: `  # Enrich by name + company (key from LUSHA_API_KEY)
  brutus enum lusha --first-name Ada --last-name Lovelace --company Analytical

  # Enrich by name + company domain
  brutus enum lusha --first-name Ada --last-name Lovelace --domain example.com

  # Enrich by email
  brutus enum lusha --email ada@example.com

  # Enrich by LinkedIn URL, also request phone numbers
  brutus enum lusha --linkedin https://linkedin.com/in/ada --phone

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum lusha --email ada@example.com --api-key abc123`,
	RunE: runEnumLusha,
}

func init() {
	f := enumLushaCmd.Flags()
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
	// No MarkFlagRequired — identity is validated in runEnumLusha.
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

	client := lusha.NewClient(apiKey, flagTimeout)
	contact, err := client.Enrich(ctx, query, reveal)
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

// validateLushaIdentity enforces that exactly one identity group is set:
// (1) name group: --first-name + --last-name + exactly one of (--company | --domain),
// (2) --email, or (3) --linkedin. --phone and --email-only are mutually exclusive.
// Pure function over the flag values — no network, trivially testable.
func validateLushaIdentity() error {
	if flagLushaPhone && flagLushaEmailOnly {
		return fmt.Errorf("--phone and --email-only are mutually exclusive")
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
// messages. It returns only static, status-derived text and never echoes the
// vendor's APIError.Details (which could carry the key) (P0-1).
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
	// never its Details, whose Error() can echo the request body or even the key
	// back (P0-1). Otherwise report a generic, key-free message (never
	// %w-wrapping the underlying error, whose Error() embeds Details).
	var apiErr *lusha.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("lusha enrichment failed (HTTP %d)", apiErr.StatusCode)
	}
	return fmt.Errorf("lusha enrichment failed")
}
