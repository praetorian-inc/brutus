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

var enumPassiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "API-key OSINT/HUMINT sources — employee email/contact discovery & enrichment",
	Long: `Passive OSINT/HUMINT sources that discover and enrich employee emails and
contacts for a domain via third-party provider APIs. Each source requires its
own API key and consumes that provider's API credits — see the per-source help
for the relevant environment variable and credit model.

Sources:
  hunter     Discover people and emails via Hunter.io Domain Search
  apollo     Discover and enrich people for a domain via Apollo.io
  lusha      Enrich a single contact (email/phone) via Lusha
  dehashed   Collect breach-exposed identity data for a domain via DeHashed
  linkedin   Scrape LinkedIn Sales Navigator profiles via PhantomBuster

These sources are standalone — they do not feed the saas enumeration pipeline.`,
	Example: `  # Discover people via Hunter.io
  brutus enum passive hunter --domain example.com

  # Discover and enrich people via Apollo.io
  brutus enum passive apollo --domain example.com

  # Enrich a contact via Lusha
  brutus enum passive lusha --first-name Jane --last-name Doe --company "Example Inc"

  # Collect breach-exposed identity data via DeHashed
  brutus enum passive dehashed --domain example.com

  # Scrape LinkedIn Sales Navigator profiles via PhantomBuster
  brutus enum passive linkedin --agent-id 1234567890`,
}
