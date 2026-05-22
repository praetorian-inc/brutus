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
	flagEnumDomain string
	flagEnumFormat string
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate accounts against SaaS services or Active Directory",
	Long: `Enumerate email accounts against SaaS services (Microsoft 365, Google Workspace, etc.)
or enumerate Active Directory usernames via Kerberos AS-REQ.

Subcommands:
  saas       Enumerate email accounts against SaaS services
  kerberos   Enumerate Active Directory users via Kerberos AS-REQ
  generate   Generate email addresses or usernames from embedded name lists

See subcommand help for details:
  brutus enum saas --help
  brutus enum kerberos --help
  brutus enum generate --help`,
	Example: `  # SaaS email enumeration
  brutus enum saas --domain praetorian.com -e test@praetorian.com

  # Kerberos user enumeration
  brutus enum kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator

  # Generate emails for enumeration
  brutus enum generate --domain example.com --format flast`,
}

var enumGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate email addresses or usernames from embedded name lists",
	Long: `Generate email addresses by combining embedded first/last name wordlists
with a domain using a specified format pattern. Without --domain, generates
usernames only (for piping to other tools).

Available formats:
  first.last  john.smith (default)
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

  # Pipe to Kerberos enum
  brutus enum generate --format flast | brutus enum kerberos --dc 10.0.0.1 --domain CORP.LOCAL -U -`,
	RunE: runEnumGenerate,
}

func init() {
	// Register generate flags
	f := enumGenerateCmd.Flags()
	f.StringVarP(&flagEnumDomain, "domain", "d", "", "Domain to append to generated usernames (omit to generate usernames only)")
	f.StringVar(&flagEnumFormat, "format", "first.last", "Username format (first.last, flast, firstl, f.last, lastf, last.first, lastfirst, first)")

	// Wire commands
	enumCmd.AddCommand(enumGenerateCmd)
	enumCmd.AddCommand(enumSaasCmd)
	enumCmd.AddCommand(enumKerberosCmd)
}

// runEnumGenerate handles the "enum generate" subcommand.
func runEnumGenerate(cmd *cobra.Command, args []string) error {
	if flagEnumDomain == "" {
		// Generate usernames only (no domain)
		usernames, err := enum.GenerateUsernames(flagEnumFormat)
		if err != nil {
			return fmt.Errorf("generating usernames: %w", err)
		}
		for _, u := range usernames {
			fmt.Println(u)
		}
		return nil
	}

	// Generate emails with domain
	emails, err := enum.GenerateEmails(flagEnumFormat, flagEnumDomain)
	if err != nil {
		return fmt.Errorf("generating emails: %w", err)
	}
	for _, e := range emails {
		fmt.Println(e)
	}
	return nil
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
		defer f.Close()
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
