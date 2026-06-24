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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

// baseConfigOptions holds configuration shared across all subcommands.
type baseConfigOptions struct {
	usernames        []string
	passwords        []string
	credentials      []brutus.Credential // pre-paired user:pass (no Cartesian product)
	threads          int
	timeout          time.Duration
	connectTimeout   time.Duration // TCP connect timeout for scan dials (--connect-timeout)
	llmConfig        *brutus.LLMConfig
	useColor         bool
	quiet            bool
	verbose          bool
	useBadkeys       bool
	badkeysOnly      bool
	protocolOverride string        // Override nerva-detected protocol
	aiMode           bool          // Enable AI-powered credential detection for HTTP
	tlsMode          string        // TLS verification mode: "disable", "verify", "skip-verify"
	rateLimit        float64       // Max requests per second (0 = unlimited)
	jitter           time.Duration // Random delay variance for rate limiting
	maxAttempts      int
	maxRetries       int
	mode             string // Aggressiveness tier: cautious, default, aggressive
	anthropicKey     string // ANTHROPIC_API_KEY (read once in main)
	perplexityKey    string // PERPLEXITY_API_KEY (read once in main)
	proxyURL         string // SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080")
	noNLAProbe       bool   // disable the pre-WASM NLA negotiation probe (logon scan path)
	fast             bool   // --fast triage mode: short settle budget + never-clean invariant

	// checks selects which logon-screen backdoor check(s) the scan path runs.
	// The zero value (CheckBoth) runs both, matching the combined "brutus logon"
	// command; the single subcommands set CheckStickyKeys/CheckUtilman.
	checks logon.Check

	// protocolFilter is an optional function that determines whether a discovered
	// protocol should be processed. Used by subcommands to filter services in
	// pipeline/fingerprint modes. nil means accept all protocols (legacy behavior).
	protocolFilter func(protocol string) bool
}

// webConfig holds settings specific to the web subcommand.
type webConfig struct {
	browserTimeout time.Duration
	browserTabs    int
	browserVisible bool
	useHTTPS       bool
}

// logonConfig holds settings specific to the logon subcommand.
type logonConfig struct {
	execCmd     string // command to execute via backdoor
	webTerminal bool   // start interactive web terminal
	openBrowser bool   // auto-open browser for web terminal
}

// runConfig bundles baseConfigOptions with optional subcommand-specific config.
// It embeds *baseConfigOptions so all shared fields are accessible directly.
type runConfig struct {
	*baseConfigOptions
	keys  [][]byte     // SSH keys (creds only)
	web   *webConfig   // browser/AI settings (web only)
	logon *logonConfig // sticky keys settings (logon only)
}

// determineTLSMode returns the appropriate TLS mode based on the --verify flag.
func determineTLSMode(verifyTLS bool) string {
	if verifyTLS {
		return "verify"
	}
	return "disable"
}
