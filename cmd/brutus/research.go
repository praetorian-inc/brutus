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
	"time"

	"github.com/praetorian-inc/brutus/internal/analyzers/claude"
	"github.com/praetorian-inc/brutus/internal/plugins/browser"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// routeHTTPWithAI detects HTTP auth type and routes to appropriate AI credential research.
// Returns the resolved protocol ("browser" for form-based, original for basic auth) and any AI-researched credentials.
func routeHTTPWithAI(target, protocol string, base *baseConfigOptions) (string, []brutus.Credential) {
	useHTTPS := protocol == "https"
	authType, banner := brutus.DetectHTTPAuthType(target, useHTTPS, base.timeout, base.tlsMode)
	if authType == "basic" {
		logVerbose(base.verbose, "AI mode: %s uses Basic Auth, using LLM analysis", target)
		if base.llmConfig != nil && base.llmConfig.Enabled {
			creds := researchCredentialsWithLLM(target, banner, base.llmConfig, base.verbose)
			if len(creds) > 0 {
				logVerbose(base.verbose, "LLM researched %d credential pairs for %s", len(creds), target)
				return protocol, creds
			}
		}
		return protocol, nil
	}
	logVerbose(base.verbose, "AI mode: %s appears form-based, using browser automation", target)
	return "browser", nil
}


// configureVisionAnalyzer sets up Claude Vision for screenshot analysis on the browser plugin.
func configureVisionAnalyzer(plugin *browser.Plugin, apiKey string, verbose bool) {
	if apiKey != "" {
		plugin.VisionAnalyzer = &claude.Client{APIKey: apiKey}
		logVerbose(verbose, "Configured Claude Vision for screenshot analysis")
	} else {
		logVerbose(verbose, "No ANTHROPIC_API_KEY - skipping vision analysis")
	}
}

// configureCredentialResearcher sets up Perplexity for default credential lookup on the browser plugin.
func configureCredentialResearcher(plugin *browser.Plugin, apiKey string, verbose bool) {
	if apiKey != "" {
		factory := brutus.GetAnalyzerFactory("perplexity")
		if factory != nil {
			analyzer := factory(&brutus.LLMConfig{Enabled: true, Provider: "perplexity", APIKey: apiKey})
			if credAnalyzer, ok := analyzer.(brutus.CredentialAnalyzer); ok {
				plugin.CredentialResearcher = credAnalyzer
				logVerbose(verbose, "Configured Perplexity for credential research")
			}
		}
	} else {
		logVerbose(verbose, "No PERPLEXITY_API_KEY - skipping credential research")
	}
}

// researchBrowserCredentials uses Claude Vision + Perplexity for browser-based credential research.
// 1. Claude Vision analyzes the screenshot to identify the application
// 2. Perplexity researches default credentials for the identified application
// Returns the researched credentials AND the configured browser plugin (for use in Brute).
func researchBrowserCredentials(target string, base *baseConfigOptions) ([]brutus.Credential, *browser.Plugin) {
	if base.llmConfig == nil || !base.llmConfig.Enabled {
		return nil, nil
	}

	// Create the browser plugin with configured analyzers
	browserPlugin := &browser.Plugin{
		TabCount:        base.browserTabs,
		PageLoadTimeout: 15 * time.Second,
		UseHTTPS:        base.useHTTPS,
		Visible:         base.browserVisible,
		AIVerify:        base.aiVerify,
		Verbose:         base.verbose,
	}

	configureVisionAnalyzer(browserPlugin, base.anthropicKey, base.verbose)

	configureCredentialResearcher(browserPlugin, base.perplexityKey, base.verbose)

	// Call AnalyzePage to do the full two-stage AI flow
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	logVerbose(base.verbose, "Starting headless browser (this may take a few seconds on first run)...")

	pageAnalysis, credentials, err := browserPlugin.AnalyzePage(ctx, target)
	if err != nil {
		logVerbose(base.verbose, "Page analysis error: %v", err)
		return nil, nil
	}

	// Log analysis results
	if pageAnalysis != nil {
		logVerbose(base.verbose, "Vision detected: %s %s %s (login page: %v, confidence: %.2f)",
			pageAnalysis.Application.Vendor,
			pageAnalysis.Application.Model,
			pageAnalysis.Application.Type,
			pageAnalysis.IsLoginPage,
			pageAnalysis.Confidence)
	}

	if len(credentials) > 0 {
		logVerbose(base.verbose, "AI researched %d credential pairs:", len(credentials))
		for _, c := range credentials {
			logVerbose(base.verbose, "  %s:%s", c.Username, c.Password)
		}
	}

	return credentials, browserPlugin
}

// researchCredentialsWithLLM uses the configured LLM to research default credentials for a target
func researchCredentialsWithLLM(target, banner string, llmConfig *brutus.LLMConfig, verbose bool) []brutus.Credential {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds := brutus.ResearchCredentials(ctx, target, banner, llmConfig)
	if verbose && len(creds) > 0 {
		logVerbose(verbose, "LLM suggested credentials:")
		for _, c := range creds {
			logVerbose(verbose, "  %s:%s", c.Username, c.Password)
		}
	}
	return creds
}
