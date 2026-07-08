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
	"github.com/spf13/cobra"
)

var enumActiveCmd = &cobra.Command{
	Use:   "active",
	Short: "Active account-existence enumeration against live oracles & directories",
	Long: `Active enumeration probes live services directly (account-existence oracles,
Google Workspace, Microsoft 365, GitHub, Active Directory via Kerberos, Microsoft Entra ID).
Unlike the passive API-key sources, these sources send traffic to the target's
own infrastructure or to the relevant provider's public endpoints — see the
per-source help for what each one touches and whether it is authenticated.

Sources:
  oracles      Enumerate which account-existence oracles work for an organization
  google       Enumerate Google Workspace accounts (existence + SSO/IdP)
  microsoft365 Enumerate Microsoft 365 accounts (existence + federation/tenant)
  kerberos     Enumerate Active Directory users via Kerberos AS-REQ
  teams        Authenticate with Microsoft Entra ID via device code flow
  github       Enumerate GitHub accounts by email (existence + username reveal)
  custom       Enumerate against a user-supplied oracle definition`,
	Example: `  # Account-existence oracle enumeration
  brutus enum active oracles --domain example.com --known-valid admin@example.com

  # Google Workspace account enumeration
  brutus enum active google -e alice@example.com,bob@example.com

  # Microsoft 365 account enumeration
  brutus enum active microsoft365 -e alice@example.com,bob@example.com

  # Kerberos user enumeration
  brutus enum active kerberos --dc 10.0.0.1 --domain CORP.LOCAL -u administrator

  # Authenticate with Microsoft Entra ID via device code
  brutus enum active teams auth --tenant contoso.com

  # GitHub account enumeration by email
  brutus enum active github -e alice@example.com,bob@example.com

  # Enumerate against a custom oracle definition
  brutus enum active custom -f oracle.json -e jsmith,asmith`,
}
