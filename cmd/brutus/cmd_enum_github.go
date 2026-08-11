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
	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

// File-local flag variables for the "enum active github" subcommand. A separate
// block avoids cross-command flag-state bleed with the other enum subcommands.
var (
	flagGithubEnumEmails    string
	flagGithubEnumEmailFile string
	flagGithubEnumDomain    string
	flagGithubEnumFormat    string
	flagGithubEnumLimit     int
	flagGithubEnumToken     string
	flagGithubEnumNoReveal  bool
)

var enumGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "Enumerate GitHub accounts by email (existence + username reveal)",
	Long: `Check whether email addresses correspond to GitHub accounts and, with a
personal access token, reveal the GitHub username behind each one.

Existence (unauthenticated): the github.com sign-up flow exposes an
email_validity_checks endpoint that reports whether an address is already in use
(an account exists) or available (no account). No token or sign-in is required.
GitHub aggressively rate-limits this endpoint — if you see rate-limit retries,
lower --threads and/or set --rate-limit to pace requests.

Username reveal (authenticated): when a token is provided (via GITHUB_TOKEN or
--token) the existing accounts are resolved to their GitHub usernames. This
requires a PAT with the "repo" and "delete_repo" scopes: a temporary PRIVATE
repository is created, one commit per existing email is pushed with that email
as the commit author, GitHub resolves the author's login (even when email
privacy is enabled), and the temporary repository is then ALWAYS deleted. If the
cleanup delete ever fails, the repository name is printed so you can remove it
manually. Pass --no-reveal to skip this step and run existence-only even when a
token is present.

Provide targets directly with --emails/-e or --email-file/-E, or pass --domain
to generate the candidate wordlist internally from a bundled, frequency-ranked
list of statistically-likely first/last name combinations (the same generator as
"enum generate") — no piping required. --format selects the username layout and
--limit caps generation to the first N (most-likely) candidates. --domain may be
combined with -e/-E.`,
	Example: `  # Existence-only enumeration (unauthenticated)
  brutus enum active github -e alice@example.com,bob@example.com

  # Generate candidate emails for a domain and enumerate the 5000 most likely
  brutus enum active github --domain target.com --format first.last --limit 5000

  # Enumerate emails from a file
  brutus enum active github -E emails.txt

  # Reveal usernames for existing accounts (requires a PAT with repo+delete_repo)
  export GITHUB_TOKEN=ghp_...
  brutus enum active github -E emails.txt

  # Pace requests to avoid GitHub's existence-endpoint rate limiting
  brutus enum active github -E emails.txt --threads 2 --rate-limit 1`,
	RunE: runEnumGithub,
}

func init() {
	f := enumGithubCmd.Flags()
	f.StringVarP(&flagGithubEnumEmails, "emails", "e", "", "Comma-separated email addresses to check")
	f.StringVarP(&flagGithubEnumEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	f.StringVarP(&flagGithubEnumDomain, "domain", "d", "", "Generate candidate emails for this domain (statistically-likely first/last combos)")
	f.StringVar(&flagGithubEnumFormat, "format", "first.last", "Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.IntVar(&flagGithubEnumLimit, "limit", 0, "When generating with --domain, cap to the first N (most-likely) candidates (0 = all)")
	f.StringVar(&flagGithubEnumToken, "token", "", "GitHub PAT for username reveal (overrides GITHUB_TOKEN; visible in process list — prefer the env var)")
	f.BoolVar(&flagGithubEnumNoReveal, "no-reveal", false, "Skip username reveal after existence enumeration (existence-only; no token used, no temp repo created)")
	// NOTE: no -t shorthand: it collides with the global persistent --threads/-t
	// flag, which cobra merges into this subcommand at execute time.
	// --rotating-proxy is only meaningful for GitHub existence enumeration, so it
	// lives here (persistent, inherited by the `map` subcommand) rather than as a
	// global root flag that would surface — doing nothing — on every other command.
	enumGithubCmd.PersistentFlags().BoolVar(&flagRotatingProxy, "rotating-proxy", false, "Signal that --proxy rotates exit IPs (e.g. Bright Data): reduces per-IP rate-limit backoff during GitHub existence enumeration (short retry delay, higher retry ceiling). No effect on token-rate-limited reveal.")
	enumActiveCmd.AddCommand(enumGithubCmd)
}

// runEnumGithub implements the "enum active github" subcommand. Existence runs
// unauthenticated; when a token is resolved and any accounts exist, it then
// reveals their GitHub usernames.
func runEnumGithub(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	targets, err := githubEnumTargetList()
	if err != nil {
		return err
	}
	emails := enumTargetEmails(targets)
	names := enumNamesByEmail(targets)

	token := resolveGithubToken(flagGithubEnumToken, useColor)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}
	if flagRotatingProxy && proxyURL == "" {
		fmt.Fprintln(os.Stderr, "[!] github enum: --rotating-proxy has no effect without --proxy (direct connection does not rotate IPs); ignoring.")
	}

	enumerator, err := githubenum.NewEnumerator(proxyURL, flagTimeout, token, flagRotatingProxy)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against GitHub...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n", dim(useColor, SymbolInfo), heading(useColor, "GitHub Account Enumeration"))
	}

	// Stream each completed result live. Human mode prints only EXISTS rows
	// unless --verbose; JSON mode streams a JSONL line per result. A live
	// progress bar goes to stderr (suppressed under --quiet/--json); on a TTY it
	// redraws in place with percent/rate/elapsed/ETA, off-TTY it emits throttled
	// newline lines.
	total := len(emails)
	progress := newProgressReporter(os.Stderr, total, !flagQuiet && !flagJSON, useColor)
	progress.Start()
	var processed, found int
	onResult := func(res githubenum.Result) {
		// Stamp the generated name onto the result the enumerator just returned.
		// The enumerator only ever sees the address, so the name is attached
		// here; an address that came from --emails/--email-file is absent from
		// names and stays nameless.
		res.First, res.Last = enumNameFor(names, res.Email)

		processed++
		if res.Exists {
			found++
		}

		if flagJSON {
			// By design, a revealed email yields TWO JSONL records: this initial
			// existence record (no username yet), then a second, enriched record
			// emitted after reveal (carrying the resolved username). Consumers
			// should treat the later record as authoritative — this is not a bug.
			outputGithubEnumJSONL(jsonWriter, []githubenum.Result{res})
		} else if res.Exists || flagVerbose {
			// Clear the in-place bar before printing a result row so the bar's
			// partial line doesn't corrupt it; the bar redraws on the next tick.
			progress.Clear()
			outputGithubEnumResultLine(os.Stdout, res, useColor)
		}

		progress.Update(processed, fmt.Sprintf("%d found", found))
	}

	// Surface live progress during the up-front CSRF-session gate. That gate runs
	// before any email completes, so the progress bar correctly sits at 0/N;
	// against a slow or IP-blocked proxy it can retry for tens of seconds with no
	// feedback and look like a hang. Emitting a status line per attempt — with
	// the failing reason (e.g. HTTP 403) on retries — makes the wait and its
	// cause visible immediately. Interactive output only; quiet/JSON stay clean.
	// Only the existence path has this gate (the map/reveal path uses the token
	// flow), so wiring it here is sufficient.
	if !flagQuiet && !flagJSON {
		enumerator.OnSessionProgress = func(attempt, maxAttempts int, lastErr error) {
			// Clear the in-place bar before printing so the bar's partial line
			// doesn't corrupt the status line; the bar redraws on the next tick.
			progress.Clear()
			if lastErr == nil {
				fmt.Fprintf(os.Stderr, "%s Establishing GitHub session (attempt %d/%d)…\n",
					dim(useColor, SymbolInfo), attempt, maxAttempts)
				return
			}
			fmt.Fprintf(os.Stderr, "%s Establishing GitHub session (attempt %d/%d; previous: %s)…\n",
				dim(useColor, SymbolInfo), attempt, maxAttempts,
				truncate(sanitizeTerminal(lastErr.Error()), 100))
		}
	}

	results := enumerator.EnumerateWith(ctx, emails, flagThreads, flagRateLimit, flagJitter, onResult)
	progress.Stop()

	// onResult received copies, so the returned slice is still unnamed. Stamp it
	// too: the post-reveal re-emit below encodes its rows from this slice.
	for i := range results {
		results[i].First, results[i].Last = enumNameFor(names, results[i].Email)
	}

	// Username reveal: only when not disabled, a token is set, and at least one
	// account exists.
	existing := existingEmails(results)
	if !flagGithubEnumNoReveal && token != "" && len(existing) > 0 {
		if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Revealing usernames for %d existing account(s) via a temporary private repo (deleted afterward)...\n",
				dim(useColor, SymbolInfo), len(existing))
		}

		revealProgress := newProgressReporter(os.Stderr, len(existing), !flagQuiet && !flagJSON, useColor)
		revealProgress.Start()
		mapping, revErr := enumerator.RevealWith(ctx, existing, func(done, total int) {
			revealProgress.Update(done, "commits pushed")
		})
		revealProgress.Stop()
		if revErr != nil {
			// Reveal failures are non-fatal to existence results; warn and continue.
			fmt.Fprintf(os.Stderr, "%s github username reveal failed: %v\n",
				dim(useColor, SymbolInfo), revErr)
		} else {
			mergeUsernames(results, mapping)
			if flagJSON {
				// Re-emit the now-enriched results so JSONL consumers see usernames.
				// This is the intentional SECOND record per revealed email (see the
				// onResult emit above): the first record carries existence only, this
				// one carries the resolved username. Two records per email is expected.
				for i := range results {
					if results[i].Username != "" {
						outputGithubEnumJSONL(jsonWriter, []githubenum.Result{results[i]})
					}
				}
			} else {
				outputGithubEnumUsernames(os.Stdout, results, useColor)
			}
		}
	}

	if !flagJSON {
		outputGithubEnumSummary(os.Stdout, results, useColor)
	}
	return nil
}

// githubEnumTargetList resolves the email targets from --emails and
// --email-file, plus any --domain-generated candidates, each generated target
// carrying the name its username was built from. It errors when no targets are
// supplied.
func githubEnumTargetList() ([]enum.Target, error) {
	var generated []enum.Target
	if flagGithubEnumDomain != "" {
		g, err := githubEnumGenerate()
		if err != nil {
			return nil, err
		}
		generated = g
	}

	return collectGithubTargets(flagGithubEnumEmails, flagGithubEnumEmailFile, generated,
		fmt.Errorf("provide --emails/-e, --email-file/-E, or --domain"))
}

// collectGithubEmails returns just the addresses resolved by
// collectGithubTargets. The map subcommand uses it: it never generates, so none
// of its addresses have a name to carry.
func collectGithubEmails(emailsCSV, emailFile string, generated []string, noSourceErr error) ([]string, error) {
	targets := make([]enum.Target, len(generated))
	for i, e := range generated {
		targets[i] = enum.Target{Email: e}
	}
	resolved, err := collectGithubTargets(emailsCSV, emailFile, targets, noSourceErr)
	if err != nil {
		return nil, err
	}
	return enumTargetEmails(resolved), nil
}

// collectGithubTargets parses, trims, and dedups email targets from an --emails
// CSV and an --email-file (preserving first-seen order), then appends any
// pre-generated candidates. Supplied addresses carry no name, because an address
// the operator provided says nothing about whose it is; dedup keeps the
// first-seen entry, so a supplied address that a generated candidate duplicates
// stays nameless. noSourceErr is returned verbatim when no targets resolve,
// letting each subcommand phrase its own guidance (the parent allows --domain;
// the map subcommand does not).
func collectGithubTargets(emailsCSV, emailFile string, generated []enum.Target, noSourceErr error) ([]enum.Target, error) {
	var raw []enum.Target
	if emailsCSV != "" {
		for _, e := range strings.Split(emailsCSV, ",") {
			raw = append(raw, enum.Target{Email: e})
		}
	}
	if emailFile != "" {
		lines, err := loadLinesFromFile(emailFile)
		if err != nil {
			return nil, fmt.Errorf("reading --email-file: %w", err)
		}
		for _, e := range lines {
			raw = append(raw, enum.Target{Email: e})
		}
	}
	raw = append(raw, generated...)

	seen := make(map[string]struct{})
	var targets []enum.Target
	for _, t := range raw {
		t.Email = strings.TrimSpace(t.Email)
		if t.Email == "" {
			continue
		}
		if _, ok := seen[t.Email]; ok {
			continue
		}
		seen[t.Email] = struct{}{}
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		return nil, noSourceErr
	}
	return targets, nil
}

// githubEnumGenerate produces the candidate email wordlist for --domain by
// reusing the shared, frequency-ranked generator (enum.GenerateCandidates) and
// the shared capResults helper — no duplicated generation logic. Candidates, not
// bare addresses, are generated so each target keeps the name its username was
// built from, which is knowable for free here and lossy to recover later. The
// format is validated against enum.ListFormats() first. A status line goes to
// stderr (never stdout) unless quiet or JSON.
func githubEnumGenerate() ([]enum.Target, error) {
	if !slices.Contains(enum.ListFormats(), flagGithubEnumFormat) {
		return nil, fmt.Errorf("invalid --format %q; valid formats: %s",
			flagGithubEnumFormat, strings.Join(enum.ListFormats(), ", "))
	}

	candidates, err := enum.GenerateCandidates(flagGithubEnumFormat)
	if err != nil {
		return nil, fmt.Errorf("generating candidate emails: %w", err)
	}
	candidates = capResults(candidates, flagGithubEnumLimit)
	generated := make([]enum.Target, len(candidates))
	for i, c := range candidates {
		generated[i] = c.Target(flagGithubEnumDomain)
	}

	if !flagQuiet && !flagJSON {
		useColor := isColorEnabled(flagNoColor)
		fmt.Fprintf(os.Stderr, "%s Generating %s candidates for %s (%d emails)...\n",
			dim(useColor, SymbolInfo), flagGithubEnumFormat, flagGithubEnumDomain, len(generated))
		if flagGithubEnumLimit == 0 {
			fmt.Fprintf(os.Stderr, "%s (no --limit; generating the full ~%d-candidate list — pass --limit to cap)\n",
				dim(useColor, SymbolInfo), len(generated))
		}
	}

	return generated, nil
}

// resolveGithubToken returns the --token flag value if set, otherwise the
// GITHUB_TOKEN env var, otherwise "" (existence-only mode). When the flag is
// used it warns (to stderr) that the token is visible in the process list and
// shell history. The token is never logged.
func resolveGithubToken(flagValue string, useColor bool) string {
	if flagValue != "" {
		if !flagQuiet {
			fmt.Fprintf(os.Stderr,
				"%s --token is visible in the process list and shell history; prefer the GITHUB_TOKEN env var\n",
				dim(useColor, SymbolInfo))
		}
		return flagValue
	}
	return os.Getenv("GITHUB_TOKEN")
}

// existingEmails returns the emails whose existence check confirmed an account.
func existingEmails(results []githubenum.Result) []string {
	var existing []string
	for i := range results {
		if results[i].Exists {
			existing = append(existing, results[i].Email)
		}
	}
	return existing
}

// mergeUsernames writes the resolved usernames from mapping (email -> login)
// back onto the matching results in place.
func mergeUsernames(results []githubenum.Result, mapping map[string]string) {
	for i := range results {
		if login, ok := mapping[results[i].Email]; ok {
			results[i].Username = login
		}
	}
}
