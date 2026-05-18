// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package browser implements a headless browser plugin for form-based login testing.
//
// This plugin uses Chrome DevTools Protocol (via chromedp) to:
// 1. Navigate to web pages and render JavaScript
// 2. Capture screenshots for AI-based login page detection
// 3. Identify form fields and attempt authentication
//
// Unlike the http plugin which handles HTTP Basic Auth, this plugin
// handles form-based authentication commonly found on IoT devices,
// routers, printers, cameras, and enterprise applications.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/internal/analyzers/claude"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	// DefaultTabCount is the number of concurrent browser tabs
	DefaultTabCount = 3

	// DefaultPageLoadTimeout is the timeout for page navigation
	DefaultPageLoadTimeout = 15 * time.Second
)

func init() {
	brutus.Register("browser", func() brutus.Plugin {
		return &Plugin{
			TabCount:        DefaultTabCount,
			PageLoadTimeout: DefaultPageLoadTimeout,
		}
	})
}

// Plugin implements brutus.Plugin for browser-based form authentication
type Plugin struct {
	// TabCount is the number of concurrent browser tabs
	TabCount int

	// PageLoadTimeout is the timeout for page navigation
	PageLoadTimeout time.Duration

	// UseHTTPS indicates whether to use HTTPS for connections
	UseHTTPS bool

	// Visible shows the browser window instead of running headless (demo mode)
	Visible bool

	// VisionAnalyzer is the optional AI analyzer for screenshot analysis (Claude Vision)
	VisionAnalyzer claude.VisionAnalyzer

	// CredentialResearcher is the optional analyzer for credential research (Perplexity)
	CredentialResearcher brutus.CredentialAnalyzer

	// AIVerify enables Claude Vision login verification (before/after screenshot comparison)
	AIVerify bool

	// Verbose enables detailed logging
	Verbose bool
}

// Name returns the protocol name
func (p *Plugin) Name() string {
	return "browser"
}

// Test attempts form-based authentication using headless browser
//
// Pipeline (simplified - Vision analysis is done once in AnalyzePage, not per-credential):
// 1. Navigate to target URL and fill form
// 2. Submit and verify login success
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult(p.Name(), target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Set visible mode before getting browser (must be before first GetBrowser call)
	SetBrowserVisible(p.Visible)

	// Get browser instance
	browser, err := GetBrowser(p.TabCount)
	if err != nil {
		result.Error = fmt.Errorf("browser error: %w", err)
		return result
	}

	// Acquire a tab
	tabCtx, release := browser.AcquireTab()
	defer release()

	// Build URL
	url := buildURL(target, p.UseHTTPS)

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Testing %s:%s...\n", username, password)
	}

	// AI verify mode: capture screenshots and use heuristic + Claude Vision
	if p.AIVerify && p.VisionAnalyzer != nil {
		return p.testWithAIVerify(ctx, tabCtx, url, username, password, result)
	}

	// Navigate, fill form, and submit in ONE chromedp.Run call
	// This is the only reliable way to avoid context staleness issues
	submitResult, submitErr := FillAndSubmitWithNavigate(tabCtx, url, username, password, p.PageLoadTimeout+15*time.Second)
	if submitErr != nil {
		result.Error = fmt.Errorf("form submission failed: %w", submitErr)
		return result
	}

	// Verify login success using the captured post-login state
	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] After login URL: %s\n", submitResult.AfterURL)
		_, _ = fmt.Fprintf(logOutput, "[verbose] Page has password field: %v\n", submitResult.HasPassword)
	}

	// Determine success: no password field and no error indicators
	switch {
	case submitResult.HasPassword:
		// Still on login page - login failed
		result.Success = false
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Login failed (still on login page)\n")
		}
	case looksLikeLoginFailure(submitResult.AfterHTML):
		// Error indicators found
		result.Success = false
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Login failed (error indicators found)\n")
		}
	default:
		// No password field, no errors - success
		result.Success = true
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Login appears successful\n")
		}
		// In visible/demo mode, pause to show the successful login page
		if p.Visible {
			_, _ = fmt.Fprintf(logOutput, "[demo] Pausing 3s to show successful login...\n")
			time.Sleep(3 * time.Second)
		}
	}

	return result
}

// testWithAIVerify uses heuristic verification with Claude Vision fallback for ambiguous cases.
// It captures before/after screenshots and sends them to Claude Vision when the heuristic
// confidence is too low to make a reliable determination.
func (p *Plugin) testWithAIVerify(ctx, tabCtx context.Context, url, username, password string,
	result *brutus.Result) *brutus.Result {

	submitResult, submitErr := FillSubmitAndScreenshot(tabCtx, url, username, password, p.PageLoadTimeout+15*time.Second)
	if submitErr != nil {
		result.Error = fmt.Errorf("form submission failed: %w", submitErr)
		return result
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] After login URL: %s\n", submitResult.AfterURL)
		_, _ = fmt.Fprintf(logOutput, "[verbose] Page has password field: %v\n", submitResult.HasPassword)
	}

	// Run heuristic verification first (fast, no API call)
	before := VerificationState{URL: url, HTML: submitResult.BeforeHTML}
	after := VerificationState{URL: submitResult.AfterURL, HTML: submitResult.AfterHTML}
	heuristic := VerifyLogin(before, after)

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Heuristic: success=%v confidence=%.2f reason=%s\n",
			heuristic.Success, heuristic.Confidence, heuristic.Reason)
	}

	// High confidence heuristic: trust it without API call
	if heuristic.Confidence >= 0.70 {
		result.Success = heuristic.Success
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Using heuristic result (confidence %.2f)\n", heuristic.Confidence)
		}
	} else {
		// Ambiguous: use Claude Vision for verification
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Heuristic ambiguous (%.2f), using Claude Vision...\n", heuristic.Confidence)
		}

		verification, verifyErr := p.VisionAnalyzer.VerifyLogin(ctx, submitResult.BeforeScreenshot, submitResult.AfterScreenshot)
		if verifyErr != nil {
			if p.Verbose {
				_, _ = fmt.Fprintf(logOutput, "[verbose] Vision error: %v, falling back to heuristic\n", verifyErr)
			}
			result.Success = heuristic.Success
		} else {
			if p.Verbose {
				_, _ = fmt.Fprintf(logOutput, "[verbose] Vision: success=%v confidence=%.2f reason=%s\n",
					verification.Success, verification.Confidence, verification.Reason)
			}
			result.Success = verification.Success
		}
	}

	if result.Success && p.Visible {
		_, _ = fmt.Fprintf(logOutput, "[demo] Pausing 3s to show successful login...\n")
		time.Sleep(3 * time.Second)
	}

	return result
}

// AnalyzePage performs AI analysis on a page without attempting login.
// Returns the page analysis and researched credentials (if any).
// This is used by the orchestrator to get credentials before brute forcing.
func (p *Plugin) AnalyzePage(ctx context.Context, target string) (*claude.PageAnalysis, []brutus.Credential, error) {
	browserMode := "headless"
	if p.Visible {
		browserMode = "visible"
	}
	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Initializing %s browser...\n", browserMode)
	}

	// Set visible mode before getting browser (must be before first GetBrowser call)
	SetBrowserVisible(p.Visible)

	// Get browser instance
	browser, err := GetBrowser(p.TabCount)
	if err != nil {
		return nil, nil, fmt.Errorf("browser error: %w", err)
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Browser started, acquiring tab...\n")
	}

	// Acquire a tab
	tabCtx, release := browser.AcquireTab()
	defer release()

	// Build URL
	url := buildURL(target, p.UseHTTPS)

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Navigating to %s...\n", url)
	}

	// Navigate and capture screenshot in a single operation
	// This avoids chromedp context lifecycle issues between separate calls
	screenshot, err := browser.NavigateAndScreenshot(tabCtx, url, p.PageLoadTimeout+15*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("navigation/screenshot error: %w", err)
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Page loaded and screenshot captured\n")
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Screenshot captured (%d bytes)\n", len(screenshot))
	}

	// Analyze with Claude Vision
	if p.VisionAnalyzer == nil {
		return nil, nil, fmt.Errorf("vision analyzer not configured")
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Uploading screenshot to Claude Vision API...\n")
	}

	pageAnalysis, err := p.VisionAnalyzer.AnalyzeScreenshot(ctx, screenshot)
	if err != nil {
		return nil, nil, fmt.Errorf("vision analysis failed: %w", err)
	}

	if p.Verbose {
		_, _ = fmt.Fprintf(logOutput, "[verbose] Vision detected: %s %s %s (confidence: %.2f)\n",
			pageAnalysis.Application.Vendor,
			pageAnalysis.Application.Model,
			pageAnalysis.Application.Type,
			pageAnalysis.Application.Confidence)
	}

	// Start with credentials suggested by Claude Vision
	var credentials []brutus.Credential
	if len(pageAnalysis.SuggestedCredentials) > 0 {
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Claude Vision suggested %d credential pairs\n", len(pageAnalysis.SuggestedCredentials))
		}
		for _, c := range pageAnalysis.SuggestedCredentials {
			credentials = append(credentials, brutus.Credential{
				Username: c.Username,
				Password: c.Password,
			})
		}
	}

	// Research additional credentials with Perplexity (if configured)
	if p.CredentialResearcher != nil && pageAnalysis.IsLoginPage {
		if p.Verbose {
			_, _ = fmt.Fprintf(logOutput, "[verbose] Researching additional credentials with Perplexity for %s %s...\n",
				pageAnalysis.Application.Vendor,
				pageAnalysis.Application.Model)
		}

		// Create banner from page analysis for credential research
		bannerJSON, _ := json.Marshal(pageAnalysis)
		bannerInfo := brutus.BannerInfo{
			Protocol: "browser",
			Target:   target,
			Banner:   string(bannerJSON),
		}

		perplexityCreds, err := p.CredentialResearcher.AnalyzeCredentials(ctx, bannerInfo)
		if err != nil {
			if p.Verbose {
				_, _ = fmt.Fprintf(logOutput, "[verbose] Perplexity research error: %v\n", err)
			}
			// Non-fatal - continue with Claude's suggestions
		} else if len(perplexityCreds) > 0 {
			// Merge Perplexity results, avoiding duplicates
			seen := make(map[string]bool)
			for _, c := range credentials {
				seen[c.Username+":"+c.Password] = true
			}
			added := 0
			for _, c := range perplexityCreds {
				key := c.Username + ":" + c.Password
				if !seen[key] {
					credentials = append(credentials, c)
					seen[key] = true
					added++
				}
			}
			if p.Verbose {
				_, _ = fmt.Fprintf(logOutput, "[verbose] Perplexity returned %d credentials (%d new after dedup)\n", len(perplexityCreds), added)
			}
		}
	}

	return pageAnalysis, credentials, nil
}

// logOutput is the output for verbose logging (stderr)
var logOutput io.Writer = os.Stderr

// looksLikeLoginSuccess checks if HTML indicates successful login
// We use positive indicators (success) rather than negative (failure) to be more conservative
func looksLikeLoginSuccess(html string) bool {
	html = strings.ToLower(html)

	// If password field still present, still on login page = failure
	if strings.Contains(html, "type=\"password\"") || strings.Contains(html, "type='password'") {
		return false
	}

	// Check for visible error patterns (not just CSS classes which may be hidden)
	// These are typically shown in visible text when login fails
	for _, pattern := range LoginErrorPatterns {
		if strings.Contains(html, pattern) {
			return false
		}
	}

	// Check for success indicators (dashboard, settings, logout, etc.)
	// These indicate we've moved past the login page
	for _, pattern := range LoginSuccessPatterns {
		if strings.Contains(html, pattern) {
			return true
		}
	}

	// No password field means we're not on login page anymore
	// If no clear error message, assume success
	return true
}

// looksLikeLoginFailure is the inverse of looksLikeLoginSuccess
func looksLikeLoginFailure(html string) bool {
	return !looksLikeLoginSuccess(html)
}

// buildURL constructs the full URL from target
func buildURL(target string, useHTTPS bool) string {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	return scheme + "://" + target
}
