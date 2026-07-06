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
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/google"
)

// File-local flag variables for the "enum google" subcommand. A separate block
// avoids cross-command flag-state bleed with the other enum subcommands.
var (
	flagGoogleEnumEmails    string
	flagGoogleEnumEmailFile string
	flagGoogleEnumDomain    string
	flagGoogleEnumFormat    string
	flagGoogleEnumLimit     int
)

var enumGoogleCmd = &cobra.Command{
	Use:   "google",
	Short: "Enumerate Google Workspace accounts (existence + SSO/IdP)",
	Long: `Check whether email addresses correspond to Google accounts, using two
unauthenticated oracles: the AccountChooser SSO redirect (which reveals
Workspace accounts on domains configured with single sign-on, along with the
identity provider host they redirect to) and the GXLU Gmail probe (which reveals
Gmail-enabled accounts). For each email the result is exists (with the
confirming method — workspace-sso and its IdP, or gmail) or not found.

Provide targets directly with --emails/-e or --email-file/-E, or pass --domain
to generate the candidate wordlist internally from a bundled, frequency-ranked
list of statistically-likely first/last name combinations (the same generator
as "enum generate") — no piping required. --format selects the username layout
and --limit caps generation to the first N (most-likely) candidates. --domain
may be combined with -e/-E.

This enumeration is unauthenticated: no token, credential store, or sign-in is
required.`,
	Example: `  # Enumerate a couple of emails
  brutus enum active google -e alice@example.com,bob@example.com

  # Generate candidate emails for a domain and enumerate the 5000 most likely
  brutus enum active google --domain target.com --format first.last --limit 5000

  # Enumerate emails from a file
  brutus enum active google -E emails.txt

  # Route through a SOCKS5 proxy and raise concurrency
  brutus enum active google -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20`,
	RunE: runEnumGoogle,
}

func init() {
	f := enumGoogleCmd.Flags()
	f.StringVarP(&flagGoogleEnumEmails, "emails", "e", "", "Comma-separated email addresses to check")
	f.StringVarP(&flagGoogleEnumEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	f.StringVarP(&flagGoogleEnumDomain, "domain", "d", "", "Generate candidate emails for this domain (statistically-likely first/last combos)")
	f.StringVar(&flagGoogleEnumFormat, "format", "first.last", "Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.IntVar(&flagGoogleEnumLimit, "limit", 0, "When generating with --domain, cap to the first N (most-likely) candidates (0 = all)")
	// NOTE: no -t shorthand: it collides with the global persistent --threads/-t
	// flag, which cobra merges into this subcommand at execute time.
	//
	// google lives under "active". init() runs after all package-level command
	// vars are initialized and AddCommand only needs the vars to exist, so it is
	// safe to reference enumActiveCmd (defined in cmd_enum_active.go) here.
	enumActiveCmd.AddCommand(enumGoogleCmd)
}

// runEnumGoogle implements the "enum google" subcommand.
func runEnumGoogle(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	emails, err := googleEnumTargets()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	enumerator, err := google.NewEnumerator(proxyURL, flagTimeout)
	if err != nil {
		return fmt.Errorf("google: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against Google Workspace...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n", dim(useColor, SymbolInfo), heading(useColor, "Google Workspace Account Enumeration"))
	}

	// Stream each completed result live (the callback is invoked serialized under
	// the enumerator's results mutex, so output never interleaves and never races
	// the results slice). Human mode prints only EXISTS rows unless --verbose;
	// JSON mode streams a JSONL line per result. A live progress bar goes to
	// stderr (suppressed under --quiet/--json); on a TTY it redraws in place with
	// percent/rate/elapsed/ETA, off-TTY it emits throttled newline lines.
	total := len(emails)
	progress := newProgressReporter(os.Stderr, total, !flagQuiet && !flagJSON, useColor)
	progress.Start()
	var processed, found int
	onResult := func(res google.Result) {
		processed++
		if res.Exists {
			found++
		}

		if flagJSON {
			outputGoogleEnumJSONL(jsonWriter, []google.Result{res})
		} else if res.Exists || flagVerbose {
			// Clear the in-place bar before printing a result row so the bar's
			// partial line doesn't corrupt it; the bar redraws on the next tick.
			progress.Clear()
			outputGoogleEnumResultLine(os.Stdout, res, useColor)
		}

		progress.Update(processed, fmt.Sprintf("%d found", found))
	}

	results := enumerator.EnumerateWith(ctx, emails, flagThreads, flagRateLimit, flagJitter, onResult)
	progress.Stop()

	if !flagJSON {
		outputGoogleEnumSummary(os.Stdout, results, useColor)
	}
	return nil
}

// googleEnumTargets parses, trims, and dedups the email targets from --emails
// and --email-file, plus any --domain-generated candidates. It errors when no
// targets are supplied.
func googleEnumTargets() ([]string, error) {
	var raw []string
	if flagGoogleEnumEmails != "" {
		raw = append(raw, strings.Split(flagGoogleEnumEmails, ",")...)
	}
	if flagGoogleEnumEmailFile != "" {
		lines, err := loadLinesFromFile(flagGoogleEnumEmailFile)
		if err != nil {
			return nil, fmt.Errorf("reading --email-file: %w", err)
		}
		raw = append(raw, lines...)
	}

	// --domain generates the candidate wordlist internally (reusing the same
	// ranked first/last generator as "enum generate"), so no piping is needed.
	// Generated candidates are appended to any -e/-E targets and flow through
	// the same dedup + enumeration path.
	if flagGoogleEnumDomain != "" {
		generated, err := googleEnumGenerate()
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
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		emails = append(emails, e)
	}

	if len(emails) == 0 {
		return nil, fmt.Errorf("provide --emails/-e, --email-file/-E, or --domain")
	}
	return emails, nil
}

// googleEnumGenerate produces the candidate email wordlist for --domain by
// reusing the shared, frequency-ranked generator (enum.GenerateEmails) and the
// shared capResults helper — no duplicated generation logic. The requested
// format is validated against enum.ListFormats() first, because GenerateEmails
// silently yields an empty list for an unknown format. A status line goes to
// stderr (never stdout, so --json/-o output stays clean) unless quiet or JSON.
func googleEnumGenerate() ([]string, error) {
	if !slices.Contains(enum.ListFormats(), flagGoogleEnumFormat) {
		return nil, fmt.Errorf("invalid --format %q; valid formats: %s",
			flagGoogleEnumFormat, strings.Join(enum.ListFormats(), ", "))
	}

	generated, err := enum.GenerateEmails(flagGoogleEnumFormat, flagGoogleEnumDomain)
	if err != nil {
		return nil, fmt.Errorf("generating candidate emails: %w", err)
	}
	generated = capResults(generated, flagGoogleEnumLimit)

	if !flagQuiet && !flagJSON {
		useColor := isColorEnabled(flagNoColor)
		fmt.Fprintf(os.Stderr, "%s Generating %s candidates for %s (%d emails)...\n",
			dim(useColor, SymbolInfo), flagGoogleEnumFormat, flagGoogleEnumDomain, len(generated))
		if flagGoogleEnumLimit == 0 {
			fmt.Fprintf(os.Stderr, "%s (no --limit; generating the full ~%d-candidate list — pass --limit to cap)\n",
				dim(useColor, SymbolInfo), len(generated))
		}
	}

	return generated, nil
}
