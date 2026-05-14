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
)

// baseConfigOptions holds common configuration shared across targets
type baseConfigOptions struct {
	usernames        []string
	passwords        []string
	keys             [][]byte
	threads          int
	timeout          time.Duration
	stopOnSuccess    bool
	snmpTier         string
	llmConfig        *brutus.LLMConfig
	browserTimeout   time.Duration
	browserTabs      int
	browserVisible   bool
	useHTTPS         bool
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
	sprayMode        bool
	anthropicKey     string // ANTHROPIC_API_KEY (read once in main)
	perplexityKey    string // PERPLEXITY_API_KEY (read once in main)
	stickyKeys       bool   // Sticky keys backdoor detection mode (no brute force)
	stickyKeysExec   string // Command to execute via sticky keys backdoor
	stickyKeysWeb    bool   // Start web terminal for sticky keys interaction
	stickyKeysOpen   bool   // Auto-open browser when sticky keys web terminal starts
	aiVerify         bool   // AI-powered login verification (Claude Vision before/after screenshots)
	noUtilman        bool   // Disable utilman backdoor detection (utilman runs by default with --sticky-keys)

	// protocolFilter is an optional function that determines whether a discovered
	// protocol should be processed. Used by subcommands to filter services in
	// pipeline/fingerprint modes. nil means accept all protocols (legacy behavior).
	protocolFilter func(protocol string) bool
}

// determineTLSMode returns the appropriate TLS mode based on the verify-tls flag
func determineTLSMode(verifyTLS bool) string {
	if verifyTLS {
		return "verify"
	}
	return "disable"
}
