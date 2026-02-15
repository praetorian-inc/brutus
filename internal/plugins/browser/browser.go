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

	"github.com/praetorian-inc/brutus/internal/analyzers/vision"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	// DefaultTimeout is the total timeout for browser operations
	DefaultTimeout = 60 * time.Second

	// DefaultTabCount is the number of concurrent browser tabs
	DefaultTabCount = 3

	// DefaultPageLoadTimeout is the timeout for page navigation
	DefaultPageLoadTimeout = 15 * time.Second
)

func init() {
	brutus.Register("browser", func() brutus.Plugin {
		return &Plugin{
			Timeout:         DefaultTimeout,
			TabCount:        DefaultTabCount,
			PageLoadTimeout: DefaultPageLoadTimeout,
		}
	})
}

// Plugin implements brutus.Plugin for browser-based form authentication
type Plugin struct {
	// Timeout is the total timeout for all browser operations
	Timeout time.Duration

	// TabCount is the number of concurrent browser tabs
	TabCount int

	// PageLoadTimeout is the timeout for page navigation
	PageLoadTimeout time.Duration

	// UseHTTPS indicates whether to use HTTPS for connections
	UseHTTPS bool

	// Visible shows the browser window instead of running headless (demo mode)
	Visible bool

	// VisionAnalyzer is the optional AI analyzer for screenshot analysis (Claude Vision)
	VisionAnalyzer *vision.Client

	// CredentialResearcher is the optional analyzer for credential research (Perplexity)
	CredentialResearcher brutus.CredentialAnalyzer

	// Verbose enables detailed logging
	Verbose bool

	// AIVerify uses Claude Vision to verify login success (more accurate but slower)
	AIVerify bool
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
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: p.Name(),
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Set visible mode before getting browser (must be before first GetBrowser call)
	SetBrowserVisible(p.Visible)

	// Get browser instance
	browser, err := GetBrowser(p.TabCount)
	if err != nil {
		result.Error = fmt.Errorf("browser error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Acquire a tab
	tabCtx, release := browser.AcquireTab()
	defer release()

	// Build URL
	url := buildURL(target, p.UseHTTPS)

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Testing %s:%s...\n", username, password)
	}

	// Navigate, fill form, and submit in ONE chromedp.Run call
	// This is the only reliable way to avoid context staleness issues
	submitResult, submitErr := FillAndSubmitWithNavigate(tabCtx, url, username, password, p.PageLoadTimeout+15*time.Second)
	if submitErr != nil {
		result.Error = fmt.Errorf("form submission failed: %w", submitErr)
		result.Duration = time.Since(start)
		return result
	}

	// Verify login success using the captured post-login state
	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] After login URL: %s\n", submitResult.AfterURL)
		fmt.Fprintf(logOutput, "[verbose] Page has password field: %v\n", submitResult.HasPassword)
	}

	// Determine success: no password field and no error indicators
	switch {
	case submitResult.HasPassword:
		// Still on login page - login failed
		result.Success = false
		if p.Verbose {
			fmt.Fprintf(logOutput, "[verbose] Login failed (still on login page)\n")
		}
	case looksLikeLoginFailure(submitResult.AfterHTML):
		// Error indicators found
		result.Success = false
		if p.Verbose {
			fmt.Fprintf(logOutput, "[verbose] Login failed (error indicators found)\n")
		}
	default:
		// No password field, no errors - success
		result.Success = true
		if p.Verbose {
			fmt.Fprintf(logOutput, "[verbose] Login appears successful\n")
		}
		// In visible/demo mode, pause to show the successful login page
		if p.Visible {
			fmt.Fprintf(logOutput, "[demo] Pausing 3s to show successful login...\n")
			time.Sleep(3 * time.Second)
		}
	}

	result.Duration = time.Since(start)
	return result
}

// AnalyzePage performs AI analysis on a page without attempting login.
// Returns the page analysis and researched credentials (if any).
// This is used by the orchestrator to get credentials before brute forcing.
func (p *Plugin) AnalyzePage(ctx context.Context, target string) (*vision.PageAnalysis, []brutus.Credential, error) {
	browserMode := "headless"
	if p.Visible {
		browserMode = "visible"
	}
	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Initializing %s browser...\n", browserMode)
	}

	// Set visible mode before getting browser (must be before first GetBrowser call)
	SetBrowserVisible(p.Visible)

	// Get browser instance
	browser, err := GetBrowser(p.TabCount)
	if err != nil {
		return nil, nil, fmt.Errorf("browser error: %w", err)
	}

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Browser started, acquiring tab...\n")
	}

	// Acquire a tab
	tabCtx, release := browser.AcquireTab()
	defer release()

	// Build URL
	url := buildURL(target, p.UseHTTPS)

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Navigating to %s...\n", url)
	}

	// Navigate and capture screenshot in a single operation
	// This avoids chromedp context lifecycle issues between separate calls
	screenshot, err := browser.NavigateAndScreenshot(tabCtx, url, p.PageLoadTimeout+15*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("navigation/screenshot error: %w", err)
	}

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Page loaded and screenshot captured\n")
	}

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Screenshot captured (%d bytes)\n", len(screenshot))
	}

	// Analyze with Claude Vision
	if p.VisionAnalyzer == nil {
		return nil, nil, fmt.Errorf("vision analyzer not configured")
	}

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Uploading screenshot to Claude Vision API...\n")
	}

	pageAnalysis, err := p.VisionAnalyzer.AnalyzeScreenshot(ctx, screenshot)
	if err != nil {
		return nil, nil, fmt.Errorf("vision analysis failed: %w", err)
	}

	if p.Verbose {
		fmt.Fprintf(logOutput, "[verbose] Vision detected: %s %s %s (confidence: %.2f)\n",
			pageAnalysis.Application.Vendor,
			pageAnalysis.Application.Model,
			pageAnalysis.Application.Type,
			pageAnalysis.Application.Confidence)
	}

	// Start with credentials suggested by Claude Vision
	var credentials []brutus.Credential
	if len(pageAnalysis.SuggestedCredentials) > 0 {
		if p.Verbose {
			fmt.Fprintf(logOutput, "[verbose] Claude Vision suggested %d credential pairs\n", len(pageAnalysis.SuggestedCredentials))
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
			fmt.Fprintf(logOutput, "[verbose] Researching additional credentials with Perplexity for %s %s...\n",
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
				fmt.Fprintf(logOutput, "[verbose] Perplexity research error: %v\n", err)
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
				fmt.Fprintf(logOutput, "[verbose] Perplexity returned %d credentials (%d new after dedup)\n", len(perplexityCreds), added)
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
	errorPatterns := []string{
		"invalid password",
		"invalid credentials",
		"incorrect password",
		"login failed",
		"authentication failed",
		"access denied",
		"wrong password",
		"invalid username",
		"user not found",
		"bad credentials",
		"try again",
		"please enter",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(html, pattern) {
			return false
		}
	}

	// Check for success indicators (dashboard, settings, logout, etc.)
	// These indicate we've moved past the login page
	successPatterns := []string{
		"logout",
		"log out",
		"sign out",
		"signout",
		"dashboard",
		"welcome",
		"configuration",
		"status",
		"device status",
	}

	for _, pattern := range successPatterns {
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
