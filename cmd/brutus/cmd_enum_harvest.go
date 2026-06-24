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
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
	// Blank import registers the bundled sources (bing, brave, crtsh, ddg, yahoo)
	// via their init() functions.
	_ "github.com/praetorian-inc/brutus/pkg/enum/harvest/sources"
)

// File-local flag variables for the harvest subcommand.
// Separate from other enum flags to avoid cross-command state bleed.
var (
	flagHarvestDomain  string
	flagHarvestSources string // comma list; "" = all
	flagHarvestLimit   int    // per-source cap on emails kept
)

var enumHarvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "Passively harvest emails for a domain from free, key-free sources",
	Long: `Harvest email addresses for a domain from free, no-API-key sources
(Bing, DuckDuckGo, Brave, Yahoo SERP scraping and crt.sh Certificate
Transparency), scored by how many independent sources corroborate each address.

Emails only — hosts, subdomains, and certificate names are dropped. Each source
runs independently: a source failing, rate-limiting, or returning nothing never
fails the run. Honors the shared --proxy, --threads, --rate-limit, --jitter, and
--timeout flags.`,
	Example: `  # Harvest emails for a domain from all sources
  brutus enum harvest --domain example.com

  # Only specific sources
  brutus enum harvest -d example.com --sources crtsh,bing

  # JSONL output to a file
  brutus enum harvest -d example.com -o emails.jsonl`,
	RunE: runEnumHarvest,
}

func init() {
	f := enumHarvestCmd.Flags()
	f.StringVarP(&flagHarvestDomain, "domain", "d", "", "Domain to harvest emails for (required)")
	f.StringVar(&flagHarvestSources, "sources", "", "Comma-separated source names to use (default: all)")
	f.IntVar(&flagHarvestLimit, "limit", 500, "Max emails kept per source")
	_ = enumHarvestCmd.MarkFlagRequired("domain")
}

// runEnumHarvest implements the "enum harvest" subcommand.
func runEnumHarvest(cmd *cobra.Command, args []string) error {
	useColor := isColorEnabled(flagNoColor)

	if flagHarvestDomain == "" {
		return fmt.Errorf("--domain/-d is required")
	}

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

	if !flagQuiet && !flagJSON {
		fmt.Fprintf(os.Stderr, "%s Harvesting emails for %s...\n",
			dim(useColor, SymbolInfo), flagHarvestDomain)
	}

	var sources []string
	for _, s := range strings.Split(flagHarvestSources, ",") {
		if s = strings.TrimSpace(strings.ToLower(s)); s != "" {
			sources = append(sources, s)
		}
	}

	report, err := harvest.Harvest(ctx, harvest.Options{
		Domain:    flagHarvestDomain,
		Sources:   sources,
		Threads:   flagThreads,
		Timeout:   flagTimeout,
		RateLimit: flagRateLimit,
		Jitter:    flagJitter,
		Limit:     flagHarvestLimit,
		ProxyURL:  flagProxy,
		Verbose:   flagVerbose,
	})
	if err != nil {
		return fmt.Errorf("harvest failed: %w", err)
	}

	logVerbose(flagVerbose, "Harvest returned %d emails for %s", len(report.Hits), flagHarvestDomain)

	if flagJSON {
		outputHarvestJSONL(jsonWriter, report)
	} else {
		outputHarvestHuman(os.Stdout, report, useColor)
	}
	return nil
}
