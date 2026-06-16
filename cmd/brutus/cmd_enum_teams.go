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

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// File-local flag variables for the teams subcommand.
// Separate from other enum flags to avoid cross-command state bleed.
var (
	flagTeamsTenant   string
	flagTeamsClientID string
	flagTeamsScope    string
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
  brutus enum teams auth --help`,
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
	Example: `  # Authenticate against the common tenant (interactive)
  brutus enum teams auth

  # Authenticate against a specific tenant by domain
  brutus enum teams auth --tenant contoso.com

  # Use a custom app registration and scopes
  brutus enum teams auth --client-id 00000000-0000-0000-0000-000000000000 \
    --scope "openid offline_access https://graph.microsoft.com/.default"

  # Capture the full token set as JSON
  brutus enum teams auth -o token.jsonl`,
	RunE: runEnumTeamsAuth,
}

func init() {
	f := enumTeamsAuthCmd.Flags()
	f.StringVarP(&flagTeamsTenant, "tenant", "t", "common", "Tenant ID, domain, or \"common\"")
	f.StringVar(&flagTeamsClientID, "client-id", teams.DefaultClientID, "Azure app (client) ID")
	f.StringVarP(&flagTeamsScope, "scope", "s", teams.DefaultScope, "Space-separated OAuth2 scopes")
	enumTeamsCmd.AddCommand(enumTeamsAuthCmd)
}

// runEnumTeamsAuth implements the "enum teams auth" subcommand.
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

	client := teams.NewClient(flagTeamsTenant, flagTeamsClientID, flagTeamsScope, flagTimeout)

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Starting Microsoft device code authentication...\n",
			dim(useColor, SymbolInfo))
	}

	dc, err := client.StartDeviceFlow(ctx)
	if err != nil {
		return classifyTeamsError(err)
	}

	if !flagJSON {
		outputTeamsDeviceCodeHuman(os.Stderr, dc, useColor)
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
	return nil
}

// classifyTeamsError converts teams sentinel errors into actionable messages.
// Token values and device codes never appear in error output (P0-1).
func classifyTeamsError(err error) error {
	switch {
	case errors.Is(err, teams.ErrExpiredToken):
		return fmt.Errorf("teams auth: device code expired — run again to start a new session")
	case errors.Is(err, teams.ErrAccessDenied):
		return fmt.Errorf("teams auth: access denied — user cancelled or admin blocked the request")
	default:
		return fmt.Errorf("teams auth failed: %w", err)
	}
}
