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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum/dehashed"
)

// File-local flag variables for the dehashed subcommand.
// Separate from flagEnumDomain to avoid cross-command state bleed.
var (
	flagDehashedDomain            string
	flagDehashedAPIKey            string
	flagDehashedLimit             int
	flagDehashedAllEmails         bool
	flagDehashedNoDedup           bool
	flagDehashedExcludeCombolists bool
	flagDehashedNoCredentials     bool
	flagDehashedSources           []string
	flagDehashedNoRepair          bool
	flagDehashedDetailed          bool
	flagDehashedWithCredentials   bool
)

// newEnumDehashedCmd builds the "dehashed" command. A fresh instance is
// constructed per call so the same command can be mounted under two parents (the
// canonical "enum passive dehashed" path and the hidden back-compat "enum
// dehashed" alias) without sharing one *cobra.Command. All instances bind the
// same package-level flag vars, which is fine since only one runs per invocation.
func newEnumDehashedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dehashed",
		Short: "Collect breach-exposed identity data for a domain via DeHashed",
		Long: `Query the DeHashed v2 search API to collect breach-exposed identity data
associated with a domain: emails, usernames, names, IP addresses, phone numbers,
addresses, dates of birth, and the source breach database. Standalone — does not
feed the saas enumeration pipeline.

Only use this command against domains you are authorized to assess.

This command collects breach-exposed PLAINTEXT passwords and associates them
with each contact; phone numbers are also surfaced. (Password hashes are NOT
collected.) Passwords are shown by default — treat this output as highly
sensitive and handle it only within the scope of an authorized engagement.
Use --no-credentials to suppress passwords from the output.

By default the results are refined to cut noise:
  - corporate-only: keep only records whose email is @<domain>
  - dedup: merge records that share an email into one contact
Combolist/aggregator source databases are INCLUDED by default — this is where
breach passwords overwhelmingly live, so dropping them hides the passwords this
command exists to surface. Use --exclude-combolists to drop those recycled
combolist DBs for clean, identity-only enumeration.
Opt out of the other filters with --all-emails and --no-dedup.

Use --sources to restrict results to specific source databases (exact names,
comma-separated); the scoping is pushed into the query to save credits and
enforced client-side. Truncated email local-parts (a leading character or two
dropped by broker/aggregator sources) are repaired using each record's name data
by default; use --no-repair-emails to disable that repair.

Use --detailed to emit a single structured JSON document per domain (run metadata
plus every contact with all available fields: ip addresses, addresses, dates of
birth, and breach obtained-dates). In --detailed mode passwords are OFF by
default; add --with-credentials to include the breach-exposed plaintext passwords
(hashes are never included, and --no-credentials still wins as a safety override).

Requires a DeHashed API key via the DEHASHED_API_KEY environment variable
(or the --api-key flag).

This search consumes API credits (~1 credit per page of results); use --limit
to bound the number of results (and therefore credits) per run.`,
		Example: `  # Collect refined breach contacts for a domain (key from DEHASHED_API_KEY)
  brutus enum passive dehashed --domain example.com

  # Same, but suppress the breach-exposed plaintext passwords from output
  brutus enum passive dehashed --domain example.com --no-credentials

  # Keep every email (not just @example.com), unmerged; drop combolist DBs for clean identity-only enumeration
  brutus enum passive dehashed -d example.com --all-emails --no-dedup --exclude-combolists

  # Restrict to specific source databases (exact names, comma-separated)
  brutus enum passive dehashed -d example.com --sources "Adobe,LinkedIn"

  # Disable truncated-email repair (repair is on by default)
  brutus enum passive dehashed -d example.com --no-repair-emails

  # Emit one structured JSON document with full per-contact detail + run metadata
  brutus enum passive dehashed -d example.com --detailed -o breaches.json

  # Same detailed export, including breach-exposed plaintext passwords
  brutus enum passive dehashed -d example.com --detailed --with-credentials -o breaches.json

  # Provide the key explicitly (note: visible in process list / shell history)
  brutus enum passive dehashed -d example.com --api-key abc123

  # Cap results (and credit spend) and write JSONL to a file
  brutus enum passive dehashed -d example.com --limit 50 -o breaches.jsonl`,
		RunE: runEnumDehashed,
	}

	f := cmd.Flags()
	f.StringVarP(&flagDehashedDomain, "domain", "d", "", "Domain to search (required)")
	f.StringVar(&flagDehashedAPIKey, "api-key", "",
		"DeHashed API key (overrides DEHASHED_API_KEY; WARNING: visible in process list and shell history — prefer DEHASHED_API_KEY)")
	f.IntVar(&flagDehashedLimit, "limit", 100, "Maximum number of records to collect (bounds credit spend)")
	f.BoolVar(&flagDehashedAllEmails, "all-emails", false, "Keep all emails, not just those @<domain> (disables corporate-only filtering)")
	f.BoolVar(&flagDehashedNoDedup, "no-dedup", false, "Do not merge records that share an email")
	f.BoolVar(&flagDehashedExcludeCombolists, "exclude-combolists", false, "Drop records from known aggregator/combolist source databases (combolists are included by default)")
	f.BoolVar(&flagDehashedNoCredentials, "no-credentials", false, "Suppress breach-exposed plaintext passwords from the output")
	f.StringSliceVar(&flagDehashedSources, "sources", nil, "Restrict results to these DeHashed source databases (comma-separated, exact names)")
	f.BoolVar(&flagDehashedNoRepair, "no-repair-emails", false, "Do not repair truncated email local-parts using record name data (repair is on by default)")
	f.BoolVar(&flagDehashedDetailed, "detailed", false, "Emit a single structured JSON document with full per-contact detail (ip addresses, addresses, dobs, obtained dates) and run metadata")
	f.BoolVar(&flagDehashedWithCredentials, "with-credentials", false, "Include breach-exposed plaintext passwords in --detailed output (off by default; hashes are never included)")
	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

// runEnumDehashed implements the "enum dehashed" subcommand.
func runEnumDehashed(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if flagDehashedDomain == "" {
		return fmt.Errorf("--domain/-d is required")
	}

	apiKey, err := resolveDehashedAPIKey(flagDehashedAPIKey)
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
		fmt.Fprintf(os.Stderr, "%s DeHashed search consumes ~1 API credit per page; querying %s...\n",
			dim(useColor, SymbolInfo), flagDehashedDomain)
		if len(flagDehashedSources) > 0 {
			fmt.Fprintf(os.Stderr, "%s Restricting to source databases: %s\n",
				dim(useColor, SymbolInfo), strings.Join(flagDehashedSources, ", "))
		}
	}

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}
	// Page size normally tracks --limit (capped at the API max of 100). Under
	// --sources, Limit counts POST-filter matches, so a small --limit must NOT
	// shrink the page size (that would force many tiny requests to accumulate
	// matches). Use a full page in that case.
	pageSize := min(flagDehashedLimit, 100)
	if len(flagDehashedSources) > 0 {
		pageSize = 100
	}
	client, err := dehashed.NewClient(apiKey, flagTimeout, pageSize, proxyURL)
	if err != nil {
		return err
	}
	result, err := client.SearchWithOptions(ctx, dehashed.SearchOptions{
		Domain:  flagDehashedDomain,
		Sources: flagDehashedSources,
		Limit:   flagDehashedLimit,
	})
	if err != nil {
		return classifyDehashedError(err)
	}

	entries := dehashed.Refine(result.Records, dehashed.RefineOptions{
		Domain:            flagDehashedDomain,
		CorporateOnly:     !flagDehashedAllEmails,
		Dedup:             !flagDehashedNoDedup,
		ExcludeCombolists: flagDehashedExcludeCombolists,
		RepairEmails:      !flagDehashedNoRepair,
	})

	// Verbose: log counts only — never log the key or URL (P0-1 security requirement).
	logVerbose(flagVerbose, "DeHashed returned %d records → %d contacts (total available: %d, balance: %d)",
		len(result.Records), len(entries), result.Total, result.Balance)

	showCredentials := !flagDehashedNoCredentials

	// --detailed takes precedence over the human/JSONL branch. It reuses the same
	// output-file plumbing as JSON (jsonWriter is the file when -o is set, else
	// os.Stdout). Passwords are OFF by default here; --with-credentials opts in,
	// but --no-credentials always wins as a safety override.
	if flagDehashedDetailed {
		detailedShowCreds := flagDehashedWithCredentials && !flagDehashedNoCredentials
		if err := outputDehashedDetailedJSON(jsonWriter, flagDehashedDomain, len(result.Records), result.Total, result.Balance, entries, detailedShowCreds, time.Now()); err != nil {
			return fmt.Errorf("writing detailed dehashed output: %w", err)
		}
		return nil
	}

	if flagJSON {
		outputDehashedJSONL(jsonWriter, entries, showCredentials)
	} else {
		outputDehashedHuman(os.Stdout, flagDehashedDomain, len(result.Records), result.Total, result.Balance, entries, useColor, showCredentials)
	}
	return nil
}

// resolveDehashedAPIKey returns the flag value if set, else DEHASHED_API_KEY env
// var. The key is never logged (P0-1 security requirement).
func resolveDehashedAPIKey(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if key := os.Getenv("DEHASHED_API_KEY"); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("dehashed API key required: set DEHASHED_API_KEY or pass --api-key")
}

// classifyDehashedError converts dehashed sentinel errors into actionable,
// key-free messages. It inspects only the status code via errors.As and never
// %w-wraps the *APIError (whose Error() embeds Details), so nothing
// API-key-adjacent can leak (P0-1 security requirement).
func classifyDehashedError(err error) error {
	switch {
	case errors.Is(err, dehashed.ErrUnauthorized):
		return fmt.Errorf("dehashed: invalid or missing API key (check DEHASHED_API_KEY / --api-key)")
	case errors.Is(err, dehashed.ErrPaymentRequired):
		return fmt.Errorf("dehashed: payment required or out of credits (HTTP 402)")
	case errors.Is(err, dehashed.ErrForbidden):
		return fmt.Errorf("dehashed: access forbidden (HTTP 403) — check key permissions")
	case errors.Is(err, dehashed.ErrRateLimited):
		return fmt.Errorf("dehashed: rate limit exceeded — wait and retry, or lower --limit")
	}

	var apiErr *dehashed.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("dehashed search failed (HTTP %d)", apiErr.StatusCode)
	}

	return fmt.Errorf("dehashed search failed: %w", err)
}
