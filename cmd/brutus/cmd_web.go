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
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/brutus/pkg/brutus/web"
)

var webCmd = &cobra.Command{
	Use:     "web",
	Aliases: []string{"http", "panels"},
	Short:   "Audit HTTP/web panel credentials (Basic Auth, form login, AI-powered)",
	Long: `Test credentials on HTTP services including Basic Auth, form-based login
with browser automation, and AI-powered credential detection.

For single targets, the protocol (http/https) can be inferred from the port
or the --https flag, so --protocol is optional.

Use --experimental-ai to enable Claude Vision screenshot analysis and
Perplexity-powered default credential lookup for web panels.

In pipeline/fingerprint mode, only HTTP-like services are tested.`,
	Example: `  # Single target (auto-infers http)
  brutus web --target 192.168.1.1:80 -u admin -p "admin,password"

  # HTTPS target
  brutus web --target 192.168.1.1:443 -u admin -p "admin"

  # AI-powered credential detection for web panels
  brutus web --target 192.168.1.1:80 --experimental-ai

  # Pipeline mode with Nerva JSON (only HTTP services are tested)
  naabu -host 192.168.1.0/24 -p 80,443,8080 -silent | nerva --json | brutus web --experimental-ai

  # Pipe URI targets
  echo "https://192.168.1.1:443" | brutus web --experimental-ai

  # Browser form-based login with visible browser
  brutus web --target 192.168.1.1:8080 --experimental-ai --browser-visible`,
	RunE: runWeb,
}

func init() {
	registerWebFlags(webCmd)
}

// inferHTTPProtocol determines http vs https from the target and flags.
func inferHTTPProtocol(target string, useHTTPS bool) string {
	if useHTTPS {
		return "https"
	}
	// Infer from common HTTPS ports
	parts := strings.SplitN(target, ":", 2)
	if len(parts) == 2 {
		switch parts[1] {
		case "443", "8443":
			return "https"
		}
	}
	return "http"
}

func runWeb(cmd *cobra.Command, args []string) error {
	baseConfig, err := buildConfigFromFlags(cmd)
	if err != nil {
		return err
	}

	// Web mode never uses sticky keys
	baseConfig.stickyKeys = false

	// In pipeline/fingerprint mode, only process HTTP-like protocols
	baseConfig.protocolFilter = web.IsWebProtocol

	// For single-target mode, infer protocol if not explicitly set
	if flagTarget != "" && !isFlagChanged(cmd, "protocol") {
		baseConfig.protocolOverride = inferHTTPProtocol(flagTarget, flagHTTPS)
	}

	// Sync useHTTPS with inferred/overridden protocol so the browser plugin
	// uses HTTPS when the protocol is "https" (even if --https was not set).
	if baseConfig.protocolOverride == "https" {
		baseConfig.useHTTPS = true
	}

	return runSubcommand(cmd, baseConfig)
}
