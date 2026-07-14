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
	"github.com/praetorian-inc/brutus/pkg/enum/gravatar"
)

// File-local flag variables for the "enum gravatar" subcommand. A separate block
// avoids cross-command flag-state bleed with the other enum subcommands.
var (
	flagGravatarEnumEmails    string
	flagGravatarEnumEmailFile string
	flagGravatarEnumDomain    string
	flagGravatarEnumFormat    string
	flagGravatarEnumLimit     int
)

var enumGravatarCmd = &cobra.Command{
	Use:   "gravatar",
	Short: "Enumerate accounts with a registered Gravatar (by email)",
	Long: `Check whether email addresses have a registered Gravatar, using the public
avatar endpoint as an account-existence oracle. Each email is normalized
(lower-cased and trimmed) and MD5-hashed, then the avatar is requested with
d=404 so a missing avatar returns 404 rather than a default image: HTTP 200
means a Gravatar exists for that address, 404 means none is registered. Both
outcomes are definitive.

Provide targets directly with --emails/-e or --email-file/-E, or pass --domain
to generate the candidate wordlist internally from a bundled, frequency-ranked
list of statistically-likely first/last name combinations (the same generator
as "enum generate") — no piping required. --format selects the username layout
and --limit caps generation to the first N (most-likely) candidates. --domain
may be combined with -e/-E.

This enumeration is unauthenticated: no token, credential store, or sign-in is
required.`,
	Example: `  # Enumerate a couple of emails
  brutus enum active gravatar -e alice@example.com,bob@example.com

  # Generate candidate emails for a domain and enumerate the 5000 most likely
  brutus enum active gravatar --domain target.com --format first.last --limit 5000

  # Enumerate emails from a file
  brutus enum active gravatar -E emails.txt

  # Route through a SOCKS5 proxy and raise concurrency
  brutus enum active gravatar -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20`,
	RunE: runEnumGravatar,
}

func init() {
	f := enumGravatarCmd.Flags()
	f.StringVarP(&flagGravatarEnumEmails, "emails", "e", "", "Comma-separated email addresses to check")
	f.StringVarP(&flagGravatarEnumEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	f.StringVarP(&flagGravatarEnumDomain, "domain", "d", "", "Generate candidate emails for this domain (statistically-likely first/last combos)")
	f.StringVar(&flagGravatarEnumFormat, "format", "first.last", "Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.IntVar(&flagGravatarEnumLimit, "limit", 0, "When generating with --domain, cap to the first N (most-likely) candidates (0 = all)")
	// NOTE: no -t shorthand: it collides with the global persistent --threads/-t
	// flag, which cobra merges into this subcommand at execute time.
	//
	// gravatar lives under "active". init() runs after all package-level command
	// vars are initialized and AddCommand only needs the vars to exist, so it is
	// safe to reference enumActiveCmd (defined in cmd_enum_active.go) here.
	enumActiveCmd.AddCommand(enumGravatarCmd)
}

// runEnumGravatar implements the "enum gravatar" subcommand.
func runEnumGravatar(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	emails, err := gravatarEnumTargets()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	checker, err := gravatar.NewChecker("", proxyURL, flagTimeout)
	if err != nil {
		return fmt.Errorf("gravatar: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against Gravatar...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n", dim(useColor, SymbolInfo), heading(useColor, "Gravatar Account Enumeration"))
	}

	// Stream each completed result live (the callback is invoked serialized under
	// the checker's results mutex, so output never interleaves and never races
	// the results slice). Human mode prints only EXISTS rows unless --verbose;
	// JSON mode streams a JSONL line per result. A live progress bar goes to
	// stderr (suppressed under --quiet/--json); on a TTY it redraws in place with
	// percent/rate/elapsed/ETA, off-TTY it emits throttled newline lines.
	total := len(emails)
	progress := newProgressReporter(os.Stderr, total, !flagQuiet && !flagJSON, useColor)
	progress.Start()
	var processed, found int
	onResult := func(res gravatar.Result) {
		processed++
		if res.Exists {
			found++
		}

		if flagJSON {
			outputGravatarEnumJSONL(jsonWriter, []gravatar.Result{res})
		} else if res.Exists || flagVerbose {
			// Clear the in-place bar before printing a result row so the bar's
			// partial line doesn't corrupt it; the bar redraws on the next tick.
			progress.Clear()
			outputGravatarEnumResultLine(os.Stdout, res, useColor)
		}

		progress.Update(processed, fmt.Sprintf("%d found", found))
	}

	results := checker.EnumerateWith(ctx, emails, flagThreads, flagRateLimit, flagJitter, onResult)
	progress.Stop()

	if !flagJSON {
		outputGravatarEnumSummary(os.Stdout, results, useColor)
	}
	return nil
}

// gravatarEnumTargets parses, trims, lower-cases, and dedups the email targets
// from --emails and --email-file, plus any --domain-generated candidates. It
// errors when no targets are supplied.
func gravatarEnumTargets() ([]string, error) {
	var raw []string
	if flagGravatarEnumEmails != "" {
		raw = append(raw, strings.Split(flagGravatarEnumEmails, ",")...)
	}
	if flagGravatarEnumEmailFile != "" {
		lines, err := loadLinesFromFile(flagGravatarEnumEmailFile)
		if err != nil {
			return nil, fmt.Errorf("reading --email-file: %w", err)
		}
		raw = append(raw, lines...)
	}

	// --domain generates the candidate wordlist internally (reusing the same
	// ranked first/last generator as "enum generate"), so no piping is needed.
	// Generated candidates are appended to any -e/-E targets and flow through
	// the same dedup + enumeration path.
	if flagGravatarEnumDomain != "" {
		generated, err := gravatarEnumGenerate()
		if err != nil {
			return nil, err
		}
		raw = append(raw, generated...)
	}

	seen := make(map[string]struct{})
	var emails []string
	for _, e := range raw {
		e = strings.ToLower(strings.TrimSpace(e))
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

// gravatarEnumGenerate produces the candidate email wordlist for --domain by
// reusing the shared, frequency-ranked generator (enum.GenerateEmails) and the
// shared capResults helper — no duplicated generation logic. The requested
// format is validated against enum.ListFormats() first, because GenerateEmails
// silently yields an empty list for an unknown format. A status line goes to
// stderr (never stdout, so --json/-o output stays clean) unless quiet or JSON.
func gravatarEnumGenerate() ([]string, error) {
	if !slices.Contains(enum.ListFormats(), flagGravatarEnumFormat) {
		return nil, fmt.Errorf("invalid --format %q; valid formats: %s",
			flagGravatarEnumFormat, strings.Join(enum.ListFormats(), ", "))
	}

	generated, err := enum.GenerateEmails(flagGravatarEnumFormat, flagGravatarEnumDomain)
	if err != nil {
		return nil, fmt.Errorf("generating candidate emails: %w", err)
	}
	generated = capResults(generated, flagGravatarEnumLimit)

	if !flagQuiet && !flagJSON {
		useColor := isColorEnabled(flagNoColor)
		fmt.Fprintf(os.Stderr, "%s Generating %s candidates for %s (%d emails)...\n",
			dim(useColor, SymbolInfo), flagGravatarEnumFormat, sanitizeTerminal(flagGravatarEnumDomain), len(generated))
		if flagGravatarEnumLimit == 0 {
			fmt.Fprintf(os.Stderr, "%s (no --limit; generating the full ~%d-candidate list — pass --limit to cap)\n",
				dim(useColor, SymbolInfo), len(generated))
		}
	}

	return generated, nil
}
