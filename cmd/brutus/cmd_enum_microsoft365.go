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
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
	m365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

// File-local flag variables for the "enum active microsoft365" subcommand. A
// separate block avoids cross-command flag-state bleed with the other enum
// subcommands.
var (
	flagM365EnumEmails    string
	flagM365EnumEmailFile string
	flagM365EnumDomain    string
	flagM365EnumFormat    string
	flagM365EnumLimit     int
)

var enumMicrosoft365Cmd = &cobra.Command{
	Use:   "microsoft365",
	Short: "Enumerate Microsoft 365 accounts (existence + federation/tenant)",
	Long: `Check whether email addresses correspond to Microsoft 365 accounts using the
unauthenticated GetCredentialType API on login.microsoftonline.com. For each
email the result is exists or not found, annotated with the tenant relationship
the API reveals — managed (a normal account in this tenant), different tenant
(the account exists but lives in another tenant), or domain hint — and, when the
tenant is federated, the identity-provider host the sign-in redirects to.

Provide targets directly with --emails/-e or --email-file/-E, or pass --domain
to generate the candidate wordlist internally from a bundled, frequency-ranked
list of statistically-likely first/last name combinations (the same generator
as "enum generate") — no piping required. --format selects the username layout
and --limit caps generation to the first N (most-likely) candidates. --domain
may be combined with -e/-E.

This enumeration is unauthenticated: no token, credential store, or sign-in is
required.`,
	Example: `  # Enumerate a couple of emails
  brutus enum active microsoft365 -e alice@example.com,bob@example.com

  # Generate candidate emails for a domain and enumerate the 5000 most likely
  brutus enum active microsoft365 --domain target.com --format first.last --limit 5000

  # Enumerate emails from a file
  brutus enum active microsoft365 -E emails.txt

  # Route through a SOCKS5 proxy and raise concurrency
  brutus enum active microsoft365 -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20`,
	RunE: runEnumMicrosoft365,
}

func init() {
	f := enumMicrosoft365Cmd.Flags()
	f.StringVarP(&flagM365EnumEmails, "emails", "e", "", "Comma-separated email addresses to check")
	f.StringVarP(&flagM365EnumEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	f.StringVarP(&flagM365EnumDomain, "domain", "d", "", "Generate candidate emails for this domain (statistically-likely first/last combos)")
	f.StringVar(&flagM365EnumFormat, "format", "first.last", "Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.IntVar(&flagM365EnumLimit, "limit", 0, "When generating with --domain, cap to the first N (most-likely) candidates (0 = all)")
	// NOTE: no -t shorthand: it collides with the global persistent --threads/-t
	// flag, which cobra merges into this subcommand at execute time.
	//
	// microsoft365 lives under "active". init() runs after all package-level
	// command vars are initialized and AddCommand only needs the vars to exist,
	// so it is safe to reference enumActiveCmd (defined in cmd_enum_active.go).
	enumActiveCmd.AddCommand(enumMicrosoft365Cmd)
}

// runEnumMicrosoft365 implements the "enum active microsoft365" subcommand.
func runEnumMicrosoft365(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	emails, err := microsoft365EnumTargets()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	// Pass "" for baseURL to use the default Microsoft login endpoint; proxyURL
	// (possibly empty) routes the checker's client, mirroring the Google command.
	checker, err := m365.NewChecker("", proxyURL, flagTimeout)
	if err != nil {
		return fmt.Errorf("microsoft365: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against Microsoft 365...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n", dim(useColor, SymbolInfo), heading(useColor, "Microsoft 365 Account Enumeration"))
	}

	// Stream each completed result live (the callback is invoked serialized under
	// the checker's results mutex, so output never interleaves and never races
	// the results slice). Human mode prints only EXISTS rows unless --verbose;
	// JSON mode streams a JSONL line per result. A live progress bar goes to
	// stderr (suppressed under --quiet/--json); on a TTY it redraws in place with
	// percent/rate/elapsed/ETA, off-TTY it emits throttled newline lines.
	total := len(emails)
	// Create the JSONL encoder once so streamed results reuse a single encoder
	// (only meaningfully used under --json, but harmless to always construct).
	jsonEnc := json.NewEncoder(jsonWriter)
	progress := newProgressReporter(os.Stderr, total, !flagQuiet && !flagJSON, useColor)
	progress.Start()
	var processed, found int
	onResult := func(res m365.Result) {
		processed++
		if res.Exists {
			found++
		}

		if flagJSON {
			encodeMicrosoft365EnumResult(jsonEnc, res)
		} else if res.Exists || flagVerbose {
			// Clear the in-place bar before printing a result row so the bar's
			// partial line doesn't corrupt it; the bar redraws on the next tick.
			progress.Clear()
			outputMicrosoft365EnumResultLine(os.Stdout, res, useColor)
		}

		progress.Update(processed, fmt.Sprintf("%d found", found))
	}

	results := checker.EnumerateWith(ctx, emails, flagThreads, flagRateLimit, flagJitter, onResult)
	progress.Stop()

	if !flagJSON {
		outputMicrosoft365EnumSummary(os.Stdout, results, useColor)
	}
	return nil
}

// microsoft365EnumTargets parses, trims, and dedups the email targets from
// --emails and --email-file, plus any --domain-generated candidates. It errors
// when no targets are supplied.
func microsoft365EnumTargets() ([]string, error) {
	var raw []string
	if flagM365EnumEmails != "" {
		raw = append(raw, strings.Split(flagM365EnumEmails, ",")...)
	}
	if flagM365EnumEmailFile != "" {
		lines, err := loadLinesFromFile(flagM365EnumEmailFile)
		if err != nil {
			return nil, fmt.Errorf("reading --email-file: %w", err)
		}
		raw = append(raw, lines...)
	}

	// --domain generates the candidate wordlist internally (reusing the same
	// ranked first/last generator as "enum generate"), so no piping is needed.
	// Generated candidates are appended to any -e/-E targets and flow through
	// the same dedup + enumeration path.
	if flagM365EnumDomain != "" {
		generated, err := microsoft365EnumGenerate()
		if err != nil {
			return nil, err
		}
		raw = append(raw, generated...)
	}

	seen := make(map[string]struct{})
	var emails []string
	for _, e := range raw {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// Key on the lowercased address (the API is case-insensitive) while
		// appending the original-cased email to the results.
		key := strings.ToLower(e)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		emails = append(emails, e)
	}

	if len(emails) == 0 {
		return nil, fmt.Errorf("provide --emails/-e, --email-file/-E, or --domain")
	}
	return emails, nil
}

// microsoft365EnumGenerate produces the candidate email wordlist for --domain by
// reusing the shared, frequency-ranked generator (enum.GenerateEmails) and the
// shared capResults helper — no duplicated generation logic. The requested
// format is validated against enum.ListFormats() first, because GenerateEmails
// silently yields an empty list for an unknown format. A status line goes to
// stderr (never stdout, so --json/-o output stays clean) unless quiet or JSON.
func microsoft365EnumGenerate() ([]string, error) {
	if !slices.Contains(enum.ListFormats(), flagM365EnumFormat) {
		return nil, fmt.Errorf("invalid --format %q; valid formats: %s",
			flagM365EnumFormat, strings.Join(enum.ListFormats(), ", "))
	}

	generated, err := enum.GenerateEmails(flagM365EnumFormat, flagM365EnumDomain)
	if err != nil {
		return nil, fmt.Errorf("generating candidate emails: %w", err)
	}
	generated = capResults(generated, flagM365EnumLimit)

	if !flagQuiet && !flagJSON {
		useColor := isColorEnabled(flagNoColor)
		fmt.Fprintf(os.Stderr, "%s Generating %s candidates for %s (%d emails)...\n",
			dim(useColor, SymbolInfo), flagM365EnumFormat, flagM365EnumDomain, len(generated))
		if flagM365EnumLimit == 0 {
			fmt.Fprintf(os.Stderr, "%s (no --limit; generating the full ~%d-candidate list — pass --limit to cap)\n",
				dim(useColor, SymbolInfo), len(generated))
		}
	}

	return generated, nil
}
