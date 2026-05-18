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

package web

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/brutus/internal/analyzers/claude"
	"github.com/praetorian-inc/brutus/internal/plugins/browser"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// BrowserConfig holds parameters for browser-based credential research.
type BrowserConfig struct {
	Tabs          int
	Timeout       time.Duration
	UseHTTPS      bool
	Visible       bool
	AIVerify      bool
	AnthropicKey  string
	PerplexityKey string
	LLMConfig     *brutus.LLMConfig
}

// RouteHTTP detects HTTP auth type and routes to appropriate AI credential research.
// Returns the resolved protocol ("browser" for form-based, original for basic auth) and any AI-researched credentials.
func RouteHTTP(target, protocol string, timeout time.Duration, tlsMode string, llmConfig *brutus.LLMConfig) (string, []brutus.Credential) {
	useHTTPS := protocol == "https"
	authType, banner := brutus.DetectHTTPAuthType(target, useHTTPS, timeout, tlsMode)
	if authType == "basic" {
		if llmConfig != nil && llmConfig.Enabled {
			creds := ResearchCredentialsWithLLM(target, banner, llmConfig)
			if len(creds) > 0 {
				return protocol, creds
			}
		}
		return protocol, nil
	}
	return "browser", nil
}

// ResearchBrowserCredentials uses Claude Vision + Perplexity for browser-based credential research.
// Returns the researched credentials, the configured browser plugin (as a brutus.Plugin), and any error.
func ResearchBrowserCredentials(ctx context.Context, target string, cfg BrowserConfig) ([]brutus.Credential, brutus.Plugin, error) {
	if cfg.LLMConfig == nil || !cfg.LLMConfig.Enabled {
		return nil, nil, nil
	}

	browserPlugin := &browser.Plugin{
		TabCount:        cfg.Tabs,
		PageLoadTimeout: 15 * time.Second,
		UseHTTPS:        cfg.UseHTTPS,
		Visible:         cfg.Visible,
		AIVerify:        cfg.AIVerify,
	}

	if cfg.AnthropicKey != "" {
		browserPlugin.VisionAnalyzer = &claude.Client{APIKey: cfg.AnthropicKey}
	}

	if cfg.PerplexityKey != "" {
		factory := brutus.GetAnalyzerFactory("perplexity")
		if factory != nil {
			analyzer := factory(&brutus.LLMConfig{Enabled: true, Provider: "perplexity", APIKey: cfg.PerplexityKey})
			if credAnalyzer, ok := analyzer.(brutus.CredentialAnalyzer); ok {
				browserPlugin.CredentialResearcher = credAnalyzer
			}
		}
	}

	analysisCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	_, credentials, err := browserPlugin.AnalyzePage(analysisCtx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("analyzing page %s: %w", target, err)
	}

	return credentials, browserPlugin, nil
}

// ResearchCredentialsWithLLM uses the configured LLM to research default credentials for a target.
func ResearchCredentialsWithLLM(target, banner string, llmConfig *brutus.LLMConfig) []brutus.Credential {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return brutus.ResearchCredentials(ctx, target, banner, llmConfig)
}

// NewBrowserPlugin creates a basic browser plugin for form-based credential testing
// without AI analyzers. Used in non-AI mode when credentials are supplied via -c/-C.
func NewBrowserPlugin(tabs int, timeout time.Duration, useHTTPS, visible bool) brutus.Plugin {
	return &browser.Plugin{
		TabCount:        tabs,
		PageLoadTimeout: 15 * time.Second,
		UseHTTPS:        useHTTPS,
		Visible:         visible,
	}
}

// ConfigureAICredentials returns a credential slice with the AI-researched credentials
// plus an admin:admin fallback. The caller should assign this to config.Credentials.
func ConfigureAICredentials(aiCreds []brutus.Credential) []brutus.Credential {
	creds := make([]brutus.Credential, 0, len(aiCreds)+1)
	creds = append(creds, aiCreds...)
	creds = append(creds, brutus.Credential{
		Username: "admin",
		Password: "admin",
	})
	return creds
}
