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
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// File-local flag variables for the teams subcommand.
// Separate from other enum flags to avoid cross-command state bleed.
var (
	flagTeamsTenant    string
	flagTeamsClientID  string
	flagTeamsScope     string
	flagTeamsNoBrowser bool
)

// File-local flag variables for the "teams users" enumeration subcommand.
// A separate block avoids cross-command flag-state bleed with the auth path.
var (
	flagTeamsEnumEmails          string
	flagTeamsEnumEmailFile       string
	flagTeamsEnumDomain          string
	flagTeamsEnumFormat          string
	flagTeamsEnumLimit           int
	flagTeamsEnumAccessToken     string
	flagTeamsEnumRefreshToken    string
	flagTeamsEnumTokenFile       string
	flagTeamsEnumNoPresence      bool
	flagTeamsEnumTenant          string
	flagTeamsEnumClientID        string
	flagTeamsEnumScope           string
	flagTeamsEnumNoBrowser       bool
	flagTeamsEnumIncludeConsumer bool
)

// File-local flag variables for the "teams audit" subcommand. A separate block
// avoids cross-command flag-state bleed; audit takes a single --email seed
// rather than the -e/-E pair that "users" accepts.
var (
	flagTeamsAuditEmail           string
	flagTeamsAuditAccessToken     string
	flagTeamsAuditRefreshToken    string
	flagTeamsAuditTokenFile       string
	flagTeamsAuditNoPresence      bool
	flagTeamsAuditTenant          string
	flagTeamsAuditClientID        string
	flagTeamsAuditScope           string
	flagTeamsAuditNoBrowser       bool
	flagTeamsAuditIncludeConsumer bool
)

var enumTeamsCmd = &cobra.Command{
	Use:   "teams",
	Short: "Authenticate with Microsoft Entra ID via device code flow",
	Long: `Authenticate with Microsoft Entra ID (Azure AD) using the OAuth2 device
code flow. The device code flow is designed for input-constrained or headless
environments: brutus requests a short user code, you visit the verification URL
in any browser and enter that code, and brutus polls until you finish signing
in. On success it returns an access token (and, when offline_access is in the
requested scope, a refresh token).

See the auth subcommand for details:
  brutus enum active teams auth --help`,
}

var enumTeamsAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Obtain Microsoft access token and refresh token via device code flow",
	Long: `Run the Microsoft Entra ID device code OAuth2 flow and print the resulting
token set. brutus prints a verification URL and a short user code; open the URL
in a browser, enter the code, and complete the sign-in. brutus polls the token
endpoint until authorization completes, the device code expires, or the
command is interrupted.

Token values are never written to logs. In human output only a short prefix of
each token is shown; use --json (or -o) to capture the full token set.`,
	Example: `  # Authenticate against the default (organizations / work-school) tenant (interactive)
  brutus enum active teams auth

  # Headless / SSH: print the URL and code, don't open a browser
  brutus enum active teams auth --no-browser

  # Authenticate against a specific tenant by domain
  brutus enum active teams auth --tenant contoso.com

  # Use a custom app registration and scopes
  brutus enum active teams auth --client-id 00000000-0000-0000-0000-000000000000 \
    --scope "offline_access https://api.spaces.skype.com/.default"

  # Capture the full token set as JSON
  brutus enum active teams auth -o token.jsonl`,
	RunE: runEnumTeamsAuth,
}

var enumTeamsUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate corporate Microsoft Teams users by email address",
	Long: `Check whether email addresses correspond to users in a corporate Microsoft
Teams tenant, using the Teams external-search endpoint. For each email the
result is one of: exists, blocked (the tenant forbids external search but the
user may exist), not found, or unknown (auth or transport failure).

Provide targets directly with --emails/-e or --email-file/-E, or pass --domain
to generate the candidate wordlist internally from a bundled, frequency-ranked
list of statistically-likely first/last name combinations (the same generator
as "enum generate") — no piping required. --format selects the username layout
and --limit caps generation to the first N (most-likely) candidates. --domain
may be combined with -e/-E.

A valid access token is required. Provide it directly with --access-token,
reuse a token captured by "enum active teams auth -o" with --token-file, or omit both
to run the interactive device-code flow inline. When a refresh token is
available, an expired access token is refreshed once automatically; otherwise a
401 degrades gracefully to an "unknown" result.

Scope is corporate accounts only — personal/Live accounts are not supported.

Teams presence (availability and device type) is fetched by default for users
that exist; presence failures are non-fatal. Pass --no-presence to skip the
presence lookups (fewer requests).`,
	Example: `  # Device-code auth inline, then enumerate a few emails
  brutus enum active teams users -e alice@contoso.com,bob@contoso.com

  # Generate candidate emails for a domain and enumerate the 5000 most likely
  brutus enum active teams users --domain target.com --format first.last --limit 5000

  # Generate first_last candidates (presence is fetched by default for hits)
  brutus enum active teams users --domain target.com --format first_last

  # Enumerate emails from a file, skipping presence lookups
  brutus enum active teams users -E emails.txt --no-presence

  # Reuse a token captured earlier with "enum active teams auth -o"
  brutus enum active teams auth -o token.jsonl
  brutus enum active teams users -E emails.txt --token-file token.jsonl

  # Provide an access token directly
  brutus enum active teams users -e alice@contoso.com --access-token "$TOKEN"

  # Route through a SOCKS5 proxy and raise concurrency
  brutus enum active teams users -E emails.txt --proxy socks5://127.0.0.1:1080 --threads 20`,
	RunE: runEnumTeamsUsers,
}

var enumTeamsAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit a Microsoft Teams tenant's external posture into graded findings",
	Long: `Turn a single seed user's Teams enumeration result into graded security
findings about the tenant's external-exposure posture. The audit reuses the
"enum active teams users" machinery for one known-valid seed address, derives the
tenant posture, and grades it into findings (external/cross-tenant chat,
user-enumeration oracle, presence and out-of-office disclosure, and account
metadata disclosure).

A valid access token is required. Provide it directly with --access-token,
reuse a token captured by "enum active teams auth -o" with --token-file, or omit both
to run the interactive device-code flow inline. When a refresh token is
available, an expired access token is refreshed once automatically.

Scope is corporate accounts only — personal/Live accounts are not supported.

Teams presence (availability and device type) and any out-of-office note are
fetched by default, enabling the presence/out-of-office findings. Pass
--no-presence to skip the presence lookups (those findings are not evaluated).`,
	Example: `  # Audit a tenant via a single known-valid seed address (device-code auth inline)
  brutus enum active teams audit --email alice@contoso.com

  # Skip presence/out-of-office lookups (presence/OOO findings not evaluated)
  brutus enum active teams audit --email alice@contoso.com --no-presence

  # Reuse a token captured earlier with "enum active teams auth -o"
  brutus enum active teams auth -o token.jsonl
  brutus enum active teams audit --email alice@contoso.com --token-file token.jsonl

  # Emit findings as JSONL
  brutus enum active teams audit --email alice@contoso.com --json`,
	RunE: runEnumTeamsAudit,
}

func init() {
	f := enumTeamsAuthCmd.Flags()
	// NOTE: no -t shorthand: it collides with the global persistent --threads/-t
	// flag, which cobra merges into this subcommand at execute time (panic otherwise).
	f.StringVar(&flagTeamsTenant, "tenant", "organizations", "Tenant ID, domain, or \"organizations\"/\"common\"")
	f.StringVar(&flagTeamsClientID, "client-id", teams.DefaultClientID, "Azure app (client) ID")
	f.StringVarP(&flagTeamsScope, "scope", "s", teams.DefaultScope, "Space-separated OAuth2 scopes")
	f.BoolVar(&flagTeamsNoBrowser, "no-browser", false, "Don't automatically open the verification URL in a browser")
	enumTeamsCmd.AddCommand(enumTeamsAuthCmd)

	uf := enumTeamsUsersCmd.Flags()
	uf.StringVarP(&flagTeamsEnumEmails, "emails", "e", "", "Comma-separated email addresses to check")
	uf.StringVarP(&flagTeamsEnumEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	uf.StringVarP(&flagTeamsEnumDomain, "domain", "d", "", "Generate candidate emails for this domain (statistically-likely first/last combos)")
	uf.StringVar(&flagTeamsEnumFormat, "format", "first.last", "Username format for --domain generation (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	uf.IntVar(&flagTeamsEnumLimit, "limit", 0, "When generating with --domain, cap to the first N (most-likely) candidates (0 = all)")
	uf.StringVar(&flagTeamsEnumAccessToken, "access-token", "", "Access token to use (instead of device-code or --token-file)")
	uf.StringVar(&flagTeamsEnumRefreshToken, "refresh-token", "", "Refresh token used to renew an expired access token")
	uf.StringVar(&flagTeamsEnumTokenFile, "token-file", "", "JSONL token file from \"enum active teams auth -o\" to reuse")
	uf.BoolVar(&flagTeamsEnumNoPresence, "no-presence", false, "Skip Teams presence / out-of-office lookups (fewer requests; presence is gathered by default)")
	// NOTE: no -t/-s shorthands here: -t collides with the global --threads/-t
	// persistent flag, and -s is reserved for consistency with the auth path.
	uf.StringVar(&flagTeamsEnumTenant, "tenant", "organizations", "Tenant ID, domain, or \"organizations\"/\"common\" (device-code path)")
	uf.StringVar(&flagTeamsEnumClientID, "client-id", teams.DefaultClientID, "Azure app (client) ID (device-code path)")
	uf.StringVar(&flagTeamsEnumScope, "scope", teams.DefaultScope, "Space-separated OAuth2 scopes (device-code path)")
	uf.BoolVar(&flagTeamsEnumNoBrowser, "no-browser", false, "Don't automatically open the verification URL in a browser")
	uf.BoolVar(&flagTeamsEnumIncludeConsumer, "include-consumer", false, "Count consumer/personal (8:live:) Teams accounts as hits (default: only corporate 8:orgid: accounts)")
	enumTeamsCmd.AddCommand(enumTeamsUsersCmd)

	af := enumTeamsAuditCmd.Flags()
	af.StringVar(&flagTeamsAuditEmail, "email", "", "Single known-valid seed email address to audit (required)")
	af.StringVar(&flagTeamsAuditAccessToken, "access-token", "", "Access token to use (instead of device-code or --token-file)")
	af.StringVar(&flagTeamsAuditRefreshToken, "refresh-token", "", "Refresh token used to renew an expired access token")
	af.StringVar(&flagTeamsAuditTokenFile, "token-file", "", "JSONL token file from \"enum active teams auth -o\" to reuse")
	af.BoolVar(&flagTeamsAuditNoPresence, "no-presence", false, "Skip Teams presence / out-of-office lookups (fewer requests; presence is gathered by default)")
	// NOTE: no -t/-s shorthands here: -t collides with the global --threads/-t
	// persistent flag, and -s is reserved for consistency with the auth path.
	af.StringVar(&flagTeamsAuditTenant, "tenant", "organizations", "Tenant ID, domain, or \"organizations\"/\"common\" (device-code path)")
	af.StringVar(&flagTeamsAuditClientID, "client-id", teams.DefaultClientID, "Azure app (client) ID (device-code path)")
	af.StringVar(&flagTeamsAuditScope, "scope", teams.DefaultScope, "Space-separated OAuth2 scopes (device-code path)")
	af.BoolVar(&flagTeamsAuditNoBrowser, "no-browser", false, "Don't automatically open the verification URL in a browser")
	af.BoolVar(&flagTeamsAuditIncludeConsumer, "include-consumer", false, "Count consumer/personal (8:live:) Teams accounts as hits (default: only corporate 8:orgid: accounts)")
	enumTeamsCmd.AddCommand(enumTeamsAuditCmd)
}

// runEnumTeamsAuth implements the "enum active teams auth" subcommand.
func runEnumTeamsAuth(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

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

	client, err := teams.NewClient(flagTeamsTenant, flagTeamsClientID, flagTeamsScope, proxyURL, flagTimeout)
	if err != nil {
		return fmt.Errorf("teams auth: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Starting Microsoft device code authentication...\n",
			dim(useColor, SymbolInfo))
	}

	dc, err := client.StartDeviceFlow(ctx)
	if err != nil {
		return classifyTeamsError(err)
	}

	outputTeamsDeviceCodeHuman(os.Stderr, dc, useColor)

	if !flagTeamsNoBrowser {
		if openErr := openBrowser(dc.VerificationURI); openErr != nil {
			if !flagQuiet && !flagJSON {
				fmt.Fprintf(os.Stderr, "%s Couldn't open a browser automatically — open the URL above manually.\n", dim(useColor, SymbolInfo))
			}
		} else if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Opened your browser to the sign-in page — enter the code above.\n", dim(useColor, SymbolInfo))
		}
	}

	tok, err := client.WaitForToken(ctx, dc)
	if err != nil {
		return classifyTeamsError(err)
	}

	if flagJSON {
		outputTeamsTokenJSONL(jsonWriter, tok)
	} else {
		outputTeamsTokenHuman(os.Stdout, tok, useColor)
	}

	autoSaveTeamsToken(tok, useColor)
	return nil
}

// autoSaveTeamsToken persists the full token set to the default credential
// store (~/.brutus/teams.json) after a successful auth, in addition to any
// -o/--json sink. Failures are non-fatal: they emit a warning and the command
// still exits 0. Messages go to stderr (never stdout, so --json output stays
// clean) and are suppressed when quiet. Token values are never logged — only
// the file path appears (P0-1).
func autoSaveTeamsToken(tok *teams.TokenSet, useColor bool) {
	path, perr := teamsDefaultTokenPath()
	if perr != nil {
		if !flagQuiet {
			warnMsg(useColor, "couldn't determine default credential-store path: %v", perr)
		}
		return
	}

	if serr := saveTeamsTokenFile(path, tok); serr != nil {
		if !flagQuiet {
			warnMsg(useColor, "couldn't save tokens to %s: %v", path, serr)
		}
		return
	}

	if flagQuiet {
		return
	}

	fmt.Fprintf(os.Stderr, "%s%s Full tokens saved to %s (mode 0600)%s\n",
		colorIf(useColor, ColorGreen), SymbolSuccess, path, colorIf(useColor, ColorReset))
	fmt.Fprintf(os.Stderr, "%s Reuse: brutus enum active teams users -E emails.txt   (auto-loads %s)\n",
		dim(useColor, SymbolInfo), path)
	if !flagJSON && flagOutputFile == "" {
		fmt.Fprintf(os.Stderr, "%s Terminal output is truncated; full token values are in %s (or use --json / -o FILE).\n",
			dim(useColor, SymbolInfo), path)
	}
}

// runEnumTeamsUsers implements the "enum active teams users" subcommand.
func runEnumTeamsUsers(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	emails, err := teamsEnumTargets()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	accessToken, refreshToken, err := teamsEnumResolveTokens(ctx, &teamsTokenSource{
		accessToken:  flagTeamsEnumAccessToken,
		refreshToken: flagTeamsEnumRefreshToken,
		tokenFile:    flagTeamsEnumTokenFile,
		tenant:       flagTeamsEnumTenant,
		clientID:     flagTeamsEnumClientID,
		scope:        flagTeamsEnumScope,
		noBrowser:    flagTeamsEnumNoBrowser,
	}, useColor)
	if err != nil {
		return err
	}

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	enumerator, err := teams.NewEnumerator(accessToken, refreshToken, proxyURL, flagTimeout, !flagTeamsEnumNoPresence)
	if err != nil {
		return fmt.Errorf("teams users: %w", err)
	}
	enumerator.SetIncludeConsumer(flagTeamsEnumIncludeConsumer)

	// Only wire a refresh callback when a refresh token is available.
	if refreshToken != "" {
		client, cerr := teams.NewClient(flagTeamsEnumTenant, flagTeamsEnumClientID, flagTeamsEnumScope, proxyURL, flagTimeout)
		if cerr != nil {
			return fmt.Errorf("teams users: %w", cerr)
		}
		enumerator.SetRefreshFunc(func(ctx context.Context) (string, error) {
			tok, rerr := client.RefreshAccessToken(ctx, refreshToken)
			if rerr != nil {
				return "", rerr
			}
			return tok.AccessToken, nil
		})
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Enumerating %d email(s) against Microsoft Teams...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n", dim(useColor, SymbolInfo), heading(useColor, "Teams User Enumeration"))
	}

	// Stream each completed result live (the callback is invoked serialized under
	// the enumerator's results mutex, so output never interleaves and never races
	// the results slice). Human mode prints only the positive signals (EXISTS /
	// BLOCKED) unless --verbose; JSON mode streams a JSONL line per result. A live
	// progress bar goes to stderr (suppressed under --quiet/--json); on a TTY it
	// redraws in place with percent/rate/elapsed/ETA, off-TTY it emits throttled
	// newline lines.
	total := len(emails)
	progress := newProgressReporter(os.Stderr, total, !flagQuiet && !flagJSON, useColor)
	progress.Start()
	var processed, found, blocked int
	onResult := func(res teams.EnumResult) {
		processed++
		switch res.Exists {
		case teams.ExistenceYes:
			found++
		case teams.ExistenceBlocked:
			blocked++
		}

		if flagJSON {
			outputTeamsEnumJSONL(jsonWriter, []teams.EnumResult{res})
		} else {
			switch res.Exists {
			case teams.ExistenceYes, teams.ExistenceBlocked:
				// Positive signals always print. Clear the in-place bar first so
				// its partial line doesn't corrupt the row; it redraws next tick.
				progress.Clear()
				outputTeamsEnumResultLine(os.Stdout, &res, useColor)
			default:
				// ExistenceNo / ExistenceUnknown are suppressed unless --verbose.
				if flagVerbose {
					progress.Clear()
					outputTeamsEnumResultLine(os.Stdout, &res, useColor)
				}
			}
		}

		progress.Update(processed, fmt.Sprintf("%d found · %d blocked", found, blocked))
	}

	results := enumerator.EnumerateWith(ctx, emails, flagThreads, flagRateLimit, flagJitter, onResult)
	progress.Stop()

	posture := teams.DerivePosture(teamsEnumDomain(emails), results)

	if flagJSON {
		outputTeamsPostureJSONL(jsonWriter, &posture)
	} else {
		outputTeamsEnumSummary(os.Stdout, results, useColor)
		outputTeamsPostureHuman(os.Stdout, &posture, useColor)
	}
	return nil
}

// runEnumTeamsAudit implements the "enum active teams audit" subcommand.
func runEnumTeamsAudit(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(flagTeamsAuditEmail) == "" {
		return fmt.Errorf("--email <known-valid address> is required")
	}
	seedEmail := strings.TrimSpace(flagTeamsAuditEmail)

	useColor := isColorEnabled(flagNoColor)

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

	accessToken, refreshToken, err := teamsEnumResolveTokens(ctx, &teamsTokenSource{
		accessToken:  flagTeamsAuditAccessToken,
		refreshToken: flagTeamsAuditRefreshToken,
		tokenFile:    flagTeamsAuditTokenFile,
		tenant:       flagTeamsAuditTenant,
		clientID:     flagTeamsAuditClientID,
		scope:        flagTeamsAuditScope,
		noBrowser:    flagTeamsAuditNoBrowser,
	}, useColor)
	if err != nil {
		return err
	}

	presenceChecked := !flagTeamsAuditNoPresence

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	enumerator, err := teams.NewEnumerator(accessToken, refreshToken, proxyURL, flagTimeout, presenceChecked)
	if err != nil {
		return fmt.Errorf("teams audit: %w", err)
	}
	enumerator.SetIncludeConsumer(flagTeamsAuditIncludeConsumer)

	// Only wire a refresh callback when a refresh token is available.
	if refreshToken != "" {
		client, cerr := teams.NewClient(flagTeamsAuditTenant, flagTeamsAuditClientID, flagTeamsAuditScope, proxyURL, flagTimeout)
		if cerr != nil {
			return fmt.Errorf("teams audit: %w", cerr)
		}
		enumerator.SetRefreshFunc(func(ctx context.Context) (string, error) {
			tok, rerr := client.RefreshAccessToken(ctx, refreshToken)
			if rerr != nil {
				return "", rerr
			}
			return tok.AccessToken, nil
		})
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Auditing Microsoft Teams tenant via seed user...\n", dim(useColor, SymbolInfo))
	}

	result := enumerator.EnumerateOne(ctx, seedEmail)
	domain := teamsEnumDomain([]string{seedEmail})
	posture := teams.DerivePosture(domain, []teams.EnumResult{result})
	findings := teams.Audit(domain, seedEmail, &result, &posture, presenceChecked)

	// Warn (to stderr, never stdout) when the seed didn't resolve, so the user
	// knows findings are limited — but still emit whatever we gathered.
	if (result.Exists == teams.ExistenceNo || result.Exists == teams.ExistenceUnknown) && !flagQuiet {
		warnMsg(useColor, "seed email did not resolve (status: %s); findings are limited", result.Exists)
	}

	if flagJSON {
		outputTeamsAuditJSONL(jsonWriter, findings)
	} else {
		outputTeamsAuditHuman(os.Stdout, domain, &posture, findings, useColor)
	}
	return nil
}

// teamsEnumDomain derives the target domain from the email targets: the
// substring after the last "@" of the first email that has one. If the emails
// span multiple distinct domains, it returns "(multiple)"; if none contain an
// "@", it returns "".
func teamsEnumDomain(emails []string) string {
	domain := ""
	for _, e := range emails {
		at := strings.LastIndex(e, "@")
		if at < 0 || at == len(e)-1 {
			continue
		}
		d := e[at+1:]
		if domain == "" {
			domain = d
			continue
		}
		if d != domain {
			return "(multiple)"
		}
	}
	return domain
}

// teamsEnumTargets parses, trims, and dedups the email targets from --emails
// and --email-file. It errors when no targets are supplied.
func teamsEnumTargets() ([]string, error) {
	var raw []string
	if flagTeamsEnumEmails != "" {
		raw = append(raw, strings.Split(flagTeamsEnumEmails, ",")...)
	}
	if flagTeamsEnumEmailFile != "" {
		lines, err := loadLinesFromFile(flagTeamsEnumEmailFile)
		if err != nil {
			return nil, fmt.Errorf("reading --email-file: %w", err)
		}
		raw = append(raw, lines...)
	}

	// --domain generates the candidate wordlist internally (reusing the same
	// ranked first/last generator as "enum generate"), so no piping is needed.
	// Generated candidates are appended to any -e/-E targets and flow through
	// the same dedup + enumeration path.
	if flagTeamsEnumDomain != "" {
		generated, err := teamsEnumGenerate()
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

// teamsEnumGenerate produces the candidate email wordlist for --domain by
// reusing the shared, frequency-ranked generator (enum.GenerateEmails) and the
// shared capResults helper — no duplicated generation logic. The requested
// format is validated against enum.ListFormats() first, because GenerateEmails
// silently yields an empty list for an unknown format. A status line goes to
// stderr (never stdout, so --json/-o output stays clean) unless quiet or JSON.
func teamsEnumGenerate() ([]string, error) {
	if !slices.Contains(enum.ListFormats(), flagTeamsEnumFormat) {
		return nil, fmt.Errorf("invalid --format %q; valid formats: %s",
			flagTeamsEnumFormat, strings.Join(enum.ListFormats(), ", "))
	}

	generated, err := enum.GenerateEmails(flagTeamsEnumFormat, flagTeamsEnumDomain)
	if err != nil {
		return nil, fmt.Errorf("generating candidate emails: %w", err)
	}
	generated = capResults(generated, flagTeamsEnumLimit)

	if !flagQuiet && !flagJSON {
		useColor := isColorEnabled(flagNoColor)
		fmt.Fprintf(os.Stderr, "%s Generating %s candidates for %s (%d emails)...\n",
			dim(useColor, SymbolInfo), flagTeamsEnumFormat, flagTeamsEnumDomain, len(generated))
		if flagTeamsEnumLimit == 0 {
			fmt.Fprintf(os.Stderr, "%s (no --limit; generating the full ~%d-candidate list — pass --limit to cap)\n",
				dim(useColor, SymbolInfo), len(generated))
		}
	}

	return generated, nil
}

// teamsTokenSource holds the per-subcommand token-resolution inputs. Both the
// "users" and "audit" subcommands populate it from their own flag blocks so the
// shared resolution/refresh/device-code logic is reused (no duplicated HTTP
// logic). Token values are never logged.
type teamsTokenSource struct {
	accessToken  string
	refreshToken string
	tokenFile    string
	tenant       string
	clientID     string
	scope        string
	noBrowser    bool
}

// teamsEnumResolveTokens determines the access (and optional refresh) token from
// the three mutually exclusive sources in src: --token-file, --access-token, or
// an inline device-code flow. Token values are never logged.
func teamsEnumResolveTokens(ctx context.Context, src *teamsTokenSource, useColor bool) (accessToken, refreshToken string, err error) {
	if src.tokenFile != "" && src.accessToken != "" {
		return "", "", fmt.Errorf("--token-file and --access-token are mutually exclusive")
	}

	switch {
	case src.tokenFile != "":
		return teamsEnumReadTokenFile(src.tokenFile)
	case src.accessToken != "":
		return src.accessToken, src.refreshToken, nil
	}

	// No static token source: a stray --refresh-token has nothing to refresh.
	if src.refreshToken != "" {
		return "", "", fmt.Errorf("--refresh-token requires --access-token or --token-file")
	}

	// No explicit source given: try the default credential store written by
	// "enum active teams auth" so users authenticate once, then enumerate seamlessly.
	// A missing or unparseable file falls through to the device-code flow.
	if at, rt, ok := teamsEnumLoadDefaultTokens(useColor); ok {
		return at, rt, nil
	}

	return teamsEnumDeviceCodeTokens(ctx, src, useColor)
}

// teamsEnumLoadDefaultTokens attempts to load tokens from the default
// credential store (~/.brutus/teams.json). It returns ok=false (and never an
// error) when the path can't be resolved, the file doesn't exist, or it fails
// to parse, so callers fall through to the device-code flow. On success it
// prints the store path (never token values) to stderr unless quiet.
func teamsEnumLoadDefaultTokens(useColor bool) (accessToken, refreshToken string, ok bool) {
	path, err := teamsDefaultTokenPath()
	if err != nil {
		return "", "", false
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return "", "", false
	}

	at, rt, err := teamsEnumReadTokenFile(path)
	if err != nil {
		return "", "", false
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Using saved tokens from %s\n", dim(useColor, SymbolInfo), path)
	}
	return at, rt, true
}

// teamsEnumReadTokenFile reads the first JSONL line of a token file written by
// "enum active teams auth -o" and returns its access and refresh tokens.
func teamsEnumReadTokenFile(path string) (accessToken, refreshToken string, err error) {
	lines, err := loadLinesFromFile(path)
	if err != nil {
		return "", "", fmt.Errorf("reading --token-file: %w", err)
	}
	if len(lines) == 0 {
		return "", "", fmt.Errorf("--token-file %q is empty", path)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &tok); err != nil {
		return "", "", fmt.Errorf("parsing --token-file: %w", err)
	}
	if tok.AccessToken == "" {
		return "", "", fmt.Errorf("--token-file %q has no access_token", path)
	}
	return tok.AccessToken, tok.RefreshToken, nil
}

// teamsEnumDeviceCodeTokens runs the interactive device-code flow inline and
// returns the resulting access and refresh tokens.
func teamsEnumDeviceCodeTokens(ctx context.Context, src *teamsTokenSource, useColor bool) (accessToken, refreshToken string, err error) {
	proxyURL, err := resolveProxyURL()
	if err != nil {
		return "", "", err
	}

	client, err := teams.NewClient(src.tenant, src.clientID, src.scope, proxyURL, flagTimeout)
	if err != nil {
		return "", "", fmt.Errorf("teams enum: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Starting Microsoft device code authentication...\n", dim(useColor, SymbolInfo))
	}

	dc, err := client.StartDeviceFlow(ctx)
	if err != nil {
		return "", "", classifyTeamsError(err)
	}

	outputTeamsDeviceCodeHuman(os.Stderr, dc, useColor)

	if !src.noBrowser {
		if berr := openBrowser(dc.VerificationURI); berr != nil {
			if !flagQuiet && !flagJSON {
				fmt.Fprintf(os.Stderr, "%s Couldn't open a browser automatically — open the URL above manually.\n", dim(useColor, SymbolInfo))
			}
		} else if !flagQuiet && !flagJSON {
			fmt.Fprintf(os.Stderr, "%s Opened your browser to the sign-in page — enter the code above.\n", dim(useColor, SymbolInfo))
		}
	}

	tok, err := client.WaitForToken(ctx, dc)
	if err != nil {
		return "", "", classifyTeamsError(err)
	}
	return tok.AccessToken, tok.RefreshToken, nil
}

// classifyTeamsError converts teams sentinel errors into actionable messages.
// Token values and device codes never appear in error output (P0-1).
func classifyTeamsError(err error) error {
	switch {
	case errors.Is(err, teams.ErrExpiredToken):
		return fmt.Errorf("teams auth: device code expired — run again to start a new session")
	case errors.Is(err, teams.ErrAccessDenied):
		return fmt.Errorf("teams auth: access denied — user canceled or admin blocked the request")
	default:
		return fmt.Errorf("teams auth failed: %w", err)
	}
}
