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

// llm.go contains LLM integration utilities for banner analysis and credential suggestion.
//
// SECURITY NOTE: This file is the prompt injection defense surface.
// SanitizeBanner and ValidateSuggestions are the primary controls against
// malicious LLM output. Any hardening of LLM input/output processing
// should be concentrated in this file.
//
// BUILD TAG READINESS: This file has no external dependencies beyond stdlib.
// It can be guarded with "//go:build !nollm" in the future, with a companion
// llm_stub.go providing no-op fallbacks under "//go:build nollm".

package brutus

import (
	"context"
	"regexp"
	"strings"
)

const (
	// MaxBannerLength limits banner size to prevent prompt injection
	MaxBannerLength = 500
	// MaxPasswordLength limits suggested password length
	MaxPasswordLength = 32
)

var (
	// ansiRegex matches ANSI escape codes for removal
	ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// allowedPattern matches safe password characters
	allowedPattern = regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}]+$`)
)

// createAnalyzer creates the appropriate LLM analyzer based on provider configuration.
// Returns nil if provider is unknown or configuration is invalid.
// Analyzers must register themselves using RegisterAnalyzer() in their init() functions.
//
// BUILD TAG NOTE: This function calls GetAnalyzerFactory (registry.go). A future
// "nollm" stub should return nil directly without calling GetAnalyzerFactory.
func createAnalyzer(cfg *LLMConfig) BannerAnalyzer {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	// Get analyzer from registry
	factory := GetAnalyzerFactory(cfg.Provider)
	if factory == nil {
		return nil
	}

	return factory(cfg)
}

// BuildPrompt constructs the LLM prompt for banner analysis
func BuildPrompt(protocol, banner string) string {
	return `You are analyzing a service banner for penetration testing.

Protocol: ` + protocol + `
Banner (sanitized):
"""
` + banner + `
"""

Task: Suggest 3-4 likely default passwords for this specific service based on:
1. Vendor/product name in banner
2. Version numbers
3. Common defaults for this product

Return ONLY a JSON array of passwords, nothing else:
["password1", "password2", "password3"]

Rules:
- Passwords must be realistic defaults (not random)
- Max 32 characters each
- Alphanumeric + common symbols only
- NO commentary, NO explanations
`
}

// SanitizeBanner removes control chars and limits length to prevent prompt injection.
//
// SECURITY: This function is the first line of defense against prompt injection
// via crafted service banners. Known limitations (Finding 33):
// - Does not detect semantic injection patterns (e.g., "ignore previous instructions")
// - Triple-quote removal is necessary but not sufficient for all LLM providers
// - Consider adding structured output enforcement in future hardening
func SanitizeBanner(banner string) string {
	// 1. Remove null bytes
	cleaned := strings.ReplaceAll(banner, "\x00", "")

	// 2. Remove ANSI escape codes
	cleaned = ansiRegex.ReplaceAllString(cleaned, "")

	// 3. Remove triple quotes (prevent prompt escape)
	cleaned = strings.ReplaceAll(cleaned, `"""`, "")

	// 4. Limit length
	if len(cleaned) > MaxBannerLength {
		cleaned = cleaned[:MaxBannerLength]
	}

	return cleaned
}

// ValidateSuggestions ensures LLM output is safe
func ValidateSuggestions(passwords []string) []string {
	valid := []string{}

	for _, pwd := range passwords {
		// 1. Length check
		if pwd == "" || len(pwd) > MaxPasswordLength {
			continue
		}

		// 2. Character whitelist (alphanumeric + common symbols)
		if !IsValidPassword(pwd) {
			continue
		}

		valid = append(valid, pwd)
		if len(valid) >= 4 {
			break // Max 4 suggestions
		}
	}

	return valid
}

// IsValidPassword checks for safe characters
func IsValidPassword(pwd string) bool {
	// Allow: a-zA-Z0-9 and common symbols: !@#$%^&*()-_=+[]{}
	return allowedPattern.MatchString(pwd)
}

// ResearchCredentials uses the configured LLM to research default credentials
// for a target based on its banner. It first tries CredentialAnalyzer for full
// username:password pairs, falling back to BannerAnalyzer with common usernames.
func ResearchCredentials(ctx context.Context, target, banner string, llmConfig *LLMConfig) []Credential {
	if llmConfig == nil || !llmConfig.Enabled {
		return nil
	}

	factory := GetAnalyzerFactory(llmConfig.Provider)
	if factory == nil {
		return nil
	}
	analyzer := factory(llmConfig)

	bannerInfo := BannerInfo{
		Protocol: "http",
		Target:   target,
		Banner:   banner,
	}

	// Try CredentialAnalyzer first for full username:password pairs
	if credAnalyzer, ok := analyzer.(CredentialAnalyzer); ok {
		creds, err := credAnalyzer.AnalyzeCredentials(ctx, bannerInfo)
		if err != nil {
			return nil
		}
		return creds
	}

	// Fall back to password-only analysis with common usernames
	passwords, err := analyzer.Analyze(ctx, bannerInfo)
	if err != nil {
		return nil
	}

	var creds []Credential
	for _, pwd := range passwords {
		creds = append(creds,
			Credential{Username: "admin", Password: pwd},
			Credential{Username: "root", Password: pwd})
	}
	return creds
}
