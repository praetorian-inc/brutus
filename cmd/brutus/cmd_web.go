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

	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

var webCmd = &cobra.Command{
	Use:     "web",
	Aliases: []string{"http", "panels"},
	Short:   "Audit HTTP/web panel credentials (AI-powered or credential list)",
	Long: `Test credentials on HTTP services using AI-powered credential detection
or explicit credential lists.

Use --experimental-ai to enable automatic credential discovery via
Perplexity web search and Claude Vision screenshot analysis.

Alternatively, supply credentials directly with -c or -C for manual testing.

For single targets, the protocol (http/https) is auto-detected via Nerva
fingerprinting, or can be set explicitly with --protocol or --https.

In pipeline/fingerprint mode, only HTTP-like services are tested.`,
	Example: `  # AI-powered credential detection (recommended)
  brutus web --target 192.168.1.1:80 --experimental-ai

  # Pipeline mode with Nerva JSON
  naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | nerva --json | brutus web --experimental-ai

  # Manual credential list
  brutus web --target 192.168.1.1:80 -c "admin:admin,root:toor"
  brutus web --target 192.168.1.1:80 -C creds.txt

  # HTTPS target
  brutus web --target 192.168.1.1:443 --https --experimental-ai

  # Browser with visible window (demo mode)
  brutus web --target 192.168.1.1:8080 --experimental-ai --browser-visible

  # Import targets from nmap XML scan
  brutus web --nmap-file scan.xml --experimental-ai`,
	RunE: runWeb,
}

func init() {
	registerWebFlags(webCmd)
}

func runWeb(cmd *cobra.Command, args []string) error {
	base, err := buildBaseConfig(cmd)
	if err != nil {
		return err
	}

	// Load credential pairs (-c/-C)
	credPairs, err := loadCredentials(flagCredentials, flagCredentialsFile)
	if err != nil {
		return err
	}
	base.credentials = credPairs

	// AI config (opt-in)
	if base.aiMode {
		llmCfg, aiErr := setupAIConfig(true, base.anthropicKey, base.perplexityKey)
		if aiErr != nil {
			return aiErr
		}
		base.llmConfig = llmCfg
	}
	// Build web-specific config
	wc := &webConfig{
		browserTimeout: flagBrowserTimeout,
		browserTabs:    flagBrowserTabs,
		browserVisible: flagBrowserVisible,
		useHTTPS:       flagHTTPS,
	}

	// Protocol filter: only HTTP-like services
	base.protocolFilter = web.IsWebProtocol

	// --https flag sets protocol override when --protocol not explicitly set
	if flagHTTPS && !isFlagChanged(cmd, "protocol") {
		base.protocolOverride = "https"
	}
	if base.protocolOverride == "https" {
		wc.useHTTPS = true
	}

	return runSubcommand(cmd, &runConfig{baseConfigOptions: base, web: wc})
}
