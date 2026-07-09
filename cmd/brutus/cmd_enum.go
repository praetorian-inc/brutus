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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// Shared enum flag variables
var (
	flagEnumDomain        string
	flagEnumFormat        string
	flagEnumGenerateLimit int
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate accounts against account-existence oracles or Active Directory",
	Long: `Enumerate which account-existence oracles (Microsoft 365, Google Workspace, etc.)
work for an organization and enumerate emails against them, or enumerate Active
Directory usernames via Kerberos AS-REQ.

Subcommands:
  active     Active enumeration against live oracles & directories (oracles, google, microsoft365, kerberos, teams, github, custom)
  generate   Generate email addresses or usernames from embedded name lists
  passive    API-key OSINT/HUMINT sources (Hunter, Apollo, Lusha, DeHashed)

See subcommand help for details:
  brutus enum active --help
  brutus enum generate --help
  brutus enum passive --help`,
	Example: `  # Account-existence oracle enumeration
  brutus enum active oracles --domain praetorian.com -e test@praetorian.com --known-valid admin@praetorian.com

  # Kerberos user enumeration
  brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator

  # Authenticate with Microsoft Entra ID via device code
  brutus enum active teams auth --tenant contoso.com

  # GitHub account enumeration by email
  brutus enum active github -e alice@example.com,bob@example.com

  # Generate emails for enumeration
  brutus enum generate --domain example.com --format flast

  # API-key OSINT/HUMINT sources (employee email/contact discovery)
  brutus enum passive hunter --domain example.com
  brutus enum passive apollo --domain example.com
  brutus enum passive lusha --first-name Jane --last-name Doe --company "Example Inc"
  brutus enum passive dehashed --domain example.com`,
}

var enumGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate email addresses or usernames from embedded name lists",
	Long: `Generate email addresses or usernames from a bundled list of ~248,000
statistically-likely names, ranked by frequency (most likely first). Every
format is derived from the same ranked "first.last" pairs, so output is bounded
and ordered by likelihood. With --domain, the domain is appended to each
username. Use --limit to emit only the first N (most likely) entries.

Available formats:
  first.last  john.smith (default)
  first_last  john_smith
  flast       jsmith
  firstl      johns
  f.last      j.smith
  lastf       smithj
  last.first  smith.john
  lastfirst   smithjohn
  first       john`,
	Example: `  # Generate emails: jsmith@example.com
  brutus enum generate --domain example.com --format flast

  # Generate usernames only: jsmith
  brutus enum generate --format flast

  # Generate john.smith@example.com (default format)
  brutus enum generate --domain example.com

  # Emit only the 1000 most-likely emails
  brutus enum generate --domain example.com --limit 1000

  # Pipe the 500 most-likely usernames to Kerberos enum
  brutus enum generate --format flast --limit 500 | brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -`,
	RunE: runEnumGenerate,
}

func init() {
	// Register generate flags
	f := enumGenerateCmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to append to generated usernames (omit to generate usernames only)")
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format (first.last, first_last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")
	f.IntVar(&flagEnumGenerateLimit, "limit", 0, "Emit only the first N (most-likely) results (0 = no limit, emit all)")

	// generate stays a direct child of enum.
	enumCmd.AddCommand(enumGenerateCmd)

	// Canonical path: the active enumeration sources live under "active".
	// (enum active google is wired in cmd_enum_google.go init(); enum active
	// microsoft365 in cmd_enum_microsoft365.go init(); enum active github in
	// cmd_enum_github.go init().)
	enumActiveCmd.AddCommand(enumOraclesCmd)
	enumActiveCmd.AddCommand(enumKerberosCmd)
	enumActiveCmd.AddCommand(enumCustomCmd)
	enumActiveCmd.AddCommand(enumTeamsCmd)
	enumCmd.AddCommand(enumActiveCmd)

	// Canonical path: the passive API-key OSINT/HUMINT sources live under "passive".
	enumPassiveCmd.AddCommand(newEnumHunterCmd(), newEnumApolloCmd(), newEnumLushaCmd(), newEnumDehashedCmd(), newEnumLinkedinCmd())
	enumCmd.AddCommand(enumPassiveCmd)

	// Hidden back-compat aliases: the old "enum <name>" paths still work but are
	// hidden from help and marked deprecated to nudge users to "enum passive
	// <name>". A second builder instance is used per source (binding the same
	// package-level flag vars — only one runs per invocation).
	for _, alias := range []*cobra.Command{
		newEnumHunterCmd(), newEnumApolloCmd(), newEnumLushaCmd(), newEnumDehashedCmd(),
	} {
		alias.Hidden = true
		alias.Deprecated = `use "brutus enum passive ` + alias.Name() + `" instead`
		enumCmd.AddCommand(alias)
	}
}

// runEnumGenerate handles the "enum generate" subcommand.
func runEnumGenerate(cmd *cobra.Command, args []string) error {
	if flagEnumDomain == "" {
		// Generate usernames only (no domain)
		usernames, err := enum.GenerateUsernames(flagEnumFormat)
		if err != nil {
			return fmt.Errorf("generating usernames: %w", err)
		}
		for _, u := range capResults(usernames, flagEnumGenerateLimit) {
			fmt.Println(u)
		}
		return nil
	}

	// Generate emails with domain
	emails, err := enum.GenerateEmails(flagEnumFormat, flagEnumDomain)
	if err != nil {
		return fmt.Errorf("generating emails: %w", err)
	}
	for _, e := range capResults(emails, flagEnumGenerateLimit) {
		fmt.Println(e)
	}
	return nil
}

// capResults returns the first limit elements of results (the most likely,
// since results are frequency-ranked). A limit <= 0 means no cap.
func capResults(results []string, limit int) []string {
	if limit <= 0 || limit >= len(results) {
		return results
	}
	return results[:limit]
}

// pageSizeForLimit derives an API page size from a --limit total cap: min(limit,100),
// or 100 (defaultPageSize) when limit is unbounded (0). Callers pass --limit separately
// as the accumulated-total bound.
func pageSizeForLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 100 {
		return 100
	}
	return limit
}

// loadLinesFromFile reads lines from a file (one per line).
// If path is "-", reads from stdin. Used for both emails and usernames.
func loadLinesFromFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}

	var lines []string
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}
