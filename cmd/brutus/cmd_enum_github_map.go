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
	"syscall"

	"github.com/spf13/cobra"

	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

// File-local flag variables for the "enum active github map" subcommand. A
// separate block (distinct from the parent github command's flags) avoids
// cross-command flag-state bleed.
var (
	flagGithubMapEmails    string
	flagGithubMapEmailFile string
	flagGithubMapToken     string
)

var enumGithubMapCmd = &cobra.Command{
	Use:   "map",
	Short: "Correlate known emails to GitHub usernames (reveal-only, skips existence checks)",
	Long: `Correlate a list of emails you ALREADY believe are GitHub accounts to their
GitHub usernames.

map is reveal-only: it SKIPS the unauthenticated existence endpoint that the
parent "github" command uses (GitHub heavily rate-limits that endpoint) and goes
straight to the authenticated username-reveal step. Use it when you already
know — or strongly believe — the supplied emails belong to GitHub accounts and
you only need the email -> @username mapping.

map REQUIRES a personal access token (via GITHUB_TOKEN or --token) with the
"repo" and "delete_repo" scopes. It creates a temporary PRIVATE repository,
pushes one commit per email with that email as the commit author, resolves the
author's login (which works even when the account has email privacy enabled),
and then ALWAYS deletes the repository afterward. Only emails GitHub links to an
account are reported as correlated; the rest are reported as not correlated.`,
	Example: `  # Correlate emails from a file (token from the environment)
  export GITHUB_TOKEN=ghp_...
  brutus enum active github map -E emails.txt

  # Correlate a couple of emails inline
  brutus enum active github map -e alice@example.com,bob@example.com`,
	RunE: runEnumGithubMap,
}

func init() {
	f := enumGithubMapCmd.Flags()
	f.StringVarP(&flagGithubMapEmails, "emails", "e", "", "Comma-separated email addresses to correlate")
	f.StringVarP(&flagGithubMapEmailFile, "email-file", "E", "", "File of email addresses, one per line (\"-\" for stdin)")
	f.StringVar(&flagGithubMapToken, "token", "", "GitHub PAT (overrides GITHUB_TOKEN; visible in process list — prefer the env var)")
	// NOTE: no -t shorthand — it collides with the global persistent --threads/-t.
	enumGithubCmd.AddCommand(enumGithubMapCmd)
}

// runEnumGithubMap implements the "enum active github map" subcommand. It is
// reveal-only: it skips the existence endpoint and resolves the supplied emails
// straight to GitHub usernames via a temporary private repo (always deleted).
func runEnumGithubMap(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	jsonWriter, forceJSON, closeOutput, err := setupOutputWriter(flagOutputFile)
	if err != nil {
		return err
	}
	defer closeOutput()
	if forceJSON {
		flagJSON = true
	}

	emails, err := collectGithubEmails(flagGithubMapEmails, flagGithubMapEmailFile, nil,
		fmt.Errorf("provide --emails/-e or --email-file/-E"))
	if err != nil {
		return err
	}

	token := resolveGithubToken(flagGithubMapToken, useColor)
	if token == "" {
		return fmt.Errorf("github map: a GitHub PAT is required (set GITHUB_TOKEN or --token) with the \"repo\" and \"delete_repo\" scopes")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyURL, err := resolveProxyURL()
	if err != nil {
		return err
	}

	enumerator, err := githubenum.NewEnumerator(proxyURL, flagTimeout, token, flagRotatingProxy)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Correlating %d email(s) to GitHub accounts via a temporary private repo (deleted afterward)...\n",
			dim(useColor, SymbolInfo), len(emails))
		_, _ = fmt.Fprintf(os.Stdout, "\n%s %s\n\n",
			dim(useColor, SymbolInfo), heading(useColor, "GitHub Email → Account Correlation"))
	}

	progress := newProgressReporter(os.Stderr, len(emails), !flagQuiet && !flagJSON, useColor)
	progress.Start()
	mapping, revErr := enumerator.RevealWith(ctx, emails, func(done, total int) {
		progress.Update(done, "commits pushed")
	})
	progress.Stop()
	if revErr != nil {
		return fmt.Errorf("github map: %w", revErr)
	}

	results := githubMapResults(emails, mapping)

	if flagJSON {
		outputGithubEnumJSONL(jsonWriter, results)
		return nil
	}

	for i := range results {
		if results[i].Exists || flagVerbose {
			outputGithubEnumResultLine(os.Stdout, results[i], useColor)
		}
	}
	outputGithubEnumSummary(os.Stdout, results, useColor)
	return nil
}

// githubMapResults builds per-email results from the reveal mapping,
// preserving input order. An email present in the mapping correlated to a
// GitHub account (Exists=true with the resolved Username); an absent email did
// not (Exists=false).
func githubMapResults(emails []string, mapping map[string]string) []githubenum.Result {
	results := make([]githubenum.Result, len(emails))
	for i, e := range emails {
		login, ok := mapping[e]
		results[i] = githubenum.Result{Email: e, Exists: ok, Username: login}
	}
	return results
}
