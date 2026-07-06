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

	"github.com/praetorian-inc/brutus/pkg/enum/apollo"
)

// File-local flag variables for the apollo subcommand.
// Separate from flagEnumDomain to avoid cross-command state bleed.
var (
	flagApolloDomain string
	flagApolloTitles []string
	flagApolloEnrich bool
	flagApolloLimit  int
	flagApolloAPIKey string
)

// newEnumApolloCmd builds the "apollo" command. A fresh instance is constructed
// per call so the same command can be mounted under two parents (the canonical
// "enum passive apollo" path and the hidden back-compat "enum apollo" alias)
// without sharing one *cobra.Command. All instances bind the same package-level
// flag vars, which is fine since only one runs per invocation.
func newEnumApolloCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apollo",
		Short: "Discover people for a domain via Apollo.io (free; --enrich reveals emails)",
		Long: `Query the Apollo.io people-search API to DISCOVER people associated with a
company domain. By DEFAULT this is FREE and consumes NO credits: it returns thin
records (id, first name, title, organization) plus per-person AVAILABILITY flags
(whether a verified email / direct phone could be revealed) — no actual emails or
phone numbers.

Pass --enrich to reveal the full matched record for every discovered person via
the people/match API — un-obfuscated last name, verified email and status,
LinkedIn/Twitter, seniority, departments, location, and employment history. This
CONSUMES APOLLO CREDITS (one per person), bounded by --limit.

The SaaS UI performs SELECTIVE per-person enrichment (the operator picks who to
reveal) directly via the library; this CLI's --enrich is the manual full-pull.
Standalone — does not feed the saas enumeration pipeline.

Authorized use only: respect Apollo.io's Terms of Service and only enumerate
domains you are authorized to assess.

Requires an Apollo.io API key via the APOLLO_API_KEY environment variable
(or the --api-key flag).`,
		Example: `  # Discover people (DEFAULT — FREE, no credits; shows email/phone availability)
  brutus enum passive apollo --domain example.com

  # Filter by job titles
  brutus enum passive apollo -d example.com --titles "VP Engineering" --titles "CTO"

  # Enrich all discovered people (CONSUMES CREDITS, bounded by --limit)
  brutus enum passive apollo -d example.com --enrich --limit 50

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum passive apollo -d example.com --api-key abc123`,
		RunE: runEnumApollo,
	}

	f := cmd.Flags()
	f.StringVarP(&flagApolloDomain, "domain", "d", "", "Company domain to discover people for (required)")
	f.StringSliceVar(&flagApolloTitles, "titles", nil, "Optional job-title filter (repeatable or comma-separated)")
	f.BoolVar(&flagApolloEnrich, "enrich", false, "Reveal emails for all discovered people via people/match (CONSUMES CREDITS; bounded by --limit)")
	f.IntVar(&flagApolloLimit, "limit", 0, "Max people to discover AND (with --enrich) to reveal (bounds credit spend; 0 = no cap)")
	f.StringVar(&flagApolloAPIKey, "api-key", "",
		"Apollo.io API key (overrides APOLLO_API_KEY; WARNING: visible in process list and shell history — prefer APOLLO_API_KEY)")
	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

// runEnumApollo implements the "enum apollo" subcommand.
func runEnumApollo(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if flagApolloDomain == "" {
		return fmt.Errorf("--domain/-d is required")
	}

	// DISCOVER is the default (free, no credits). --enrich opts in to revealing
	// emails for every discovered person (consumes credits, bounded by --limit).
	enrich := flagApolloEnrich

	// --limit bounds discovery breadth and (with --enrich) enrich spend.
	// 0 = no cap. Reject a negative cap outright.
	if flagApolloLimit < 0 {
		return fmt.Errorf("--limit must be >= 0")
	}

	// --enrich consumes one Apollo credit per discovered person, so it must be
	// bounded. Without a positive --limit, "--enrich" against a large org would
	// reveal the entire directory and silently burn ~one credit/person — the exact
	// cost blowout this discover→enrich split exists to prevent. Free discovery may
	// still run uncapped (--limit 0); only credit-spending enrichment requires a cap.
	if enrich && flagApolloLimit <= 0 {
		return fmt.Errorf("--enrich requires a positive --limit to bound credit spend (e.g. --limit 50)")
	}

	apiKey, err := resolveApolloAPIKey(flagApolloAPIKey)
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

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Querying Apollo.io people search for %s...\n",
			dim(useColor, SymbolInfo), flagApolloDomain)
	}

	emitResult := func(result *apollo.DomainResult) {
		if result == nil {
			return
		}
		// Verbose: log counts only — never log the key or URL (P0-1 security requirement).
		logVerbose(flagVerbose, "Apollo returned %d people (total available: %d, revealed: %t)",
			len(result.People), result.Total, result.Revealed)
		if flagJSON {
			outputApolloJSONL(jsonWriter, result)
		} else {
			outputApolloHuman(os.Stdout, result, useColor)
		}
	}

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}
	client, err := apollo.NewClient(apiKey, flagTimeout, pageSizeForLimit(flagApolloLimit), proxyURL)
	if err != nil {
		return err
	}
	result, err := client.Discover(ctx, flagApolloDomain, flagApolloTitles, flagApolloLimit)
	if err != nil {
		// Output any partial discovery (Discover returns partial + err) before
		// surfacing the classified, nonzero-exit error — discovered contacts are free.
		if result != nil && len(result.People) > 0 {
			emitResult(result)
		}
		return classifyApolloError(err)
	}

	if enrich {
		// Discovery is free, so the only credit-spending action is --enrich. Warn
		// once, on stderr, with the exact count that will be charged.
		// Emit the credit-spend notice on stderr regardless of --json: stderr does
		// not corrupt stdout JSON, and --enrich is the only credit-spending path, so
		// the operator must always see the spend (unless they explicitly --quiet).
		if !flagQuiet && len(result.People) > 0 {
			fmt.Fprintf(os.Stderr, "%s --enrich will reveal emails for %d people (consumes ~%d Apollo credits)\n",
				dim(useColor, SymbolInfo), len(result.People), len(result.People))
		}
		if err := client.RevealEmails(ctx, result); err != nil {
			// Output the partial result (emails merged so far are paid for) before
			// surfacing the classified, nonzero-exit error.
			if len(result.People) > 0 {
				emitResult(result)
			}
			return classifyApolloError(err)
		}
	}

	emitResult(result)
	return nil
}

// resolveApolloAPIKey returns the flag value if set, else APOLLO_API_KEY env var.
// The key is never logged (P0-1 security requirement).
func resolveApolloAPIKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if key := os.Getenv("APOLLO_API_KEY"); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("apollo API key required: set APOLLO_API_KEY or pass --api-key")
}

// classifyApolloError converts apollo sentinel errors into actionable, key-free
// messages. For *APIError it returns ONLY status-derived text and NEVER includes
// the vendor APIError.Details — which can echo the request body or even the key
// back (P0-1). For non-API errors (network/DNS/timeout — no vendor details) it
// %w-wraps the cause to preserve debuggability.
func classifyApolloError(err error) error {
	switch {
	case errors.Is(err, apollo.ErrUnauthorized):
		return fmt.Errorf("apollo: invalid or missing API key (check APOLLO_API_KEY / --api-key)")
	case errors.Is(err, apollo.ErrForbidden):
		return fmt.Errorf("apollo: access forbidden — your plan or permissions do not allow this request")
	case errors.Is(err, apollo.ErrBadRequest):
		return fmt.Errorf("apollo: invalid request parameters (check --domain and --titles)")
	case errors.Is(err, apollo.ErrRateLimited):
		return fmt.Errorf("apollo: rate limit exceeded — wait and retry, or lower --limit")
	}
	// Unknown error. If it carries an *APIError, report only its status code —
	// never its Details (P0-1); APIError.Error() is now status-only, but we keep
	// the explicit status-code text here regardless. Otherwise (network/DNS/
	// timeout — no vendor details) %w-wrap it to preserve debuggability, matching
	// classifyHunterError.
	var apiErr *apollo.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("apollo people search failed (HTTP %d)", apiErr.StatusCode)
	}
	return fmt.Errorf("apollo people search failed: %w", err)
}
