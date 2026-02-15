// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"regexp"
	"strings"
)

// VerificationState captures page state for comparison
type VerificationState struct {
	URL  string
	HTML string
}

// VerificationResult contains login verification outcome
type VerificationResult struct {
	Success    bool
	Confidence float64
	Reason     string
}

// VerifyLogin compares before/after states to determine if login succeeded
func VerifyLogin(before, after VerificationState) VerificationResult {
	// Check 1: Error message detected (strongest signal of failure)
	if detectErrorMessage(after.HTML) {
		return VerificationResult{
			Success:    false,
			Confidence: 0.95,
			Reason:     "error_message_detected",
		}
	}

	// Check 2: URL changed to dashboard/home/admin
	if urlIndicatesSuccess(before.URL, after.URL) {
		return VerificationResult{
			Success:    true,
			Confidence: 0.90,
			Reason:     "url_changed_to_dashboard",
		}
	}

	// Check 3: Password field disappeared (form no longer visible)
	beforeHasPassword := hasPasswordField(before.HTML)
	afterHasPassword := hasPasswordField(after.HTML)

	if beforeHasPassword && !afterHasPassword {
		return VerificationResult{
			Success:    true,
			Confidence: 0.85,
			Reason:     "login_form_disappeared",
		}
	}

	// Check 4: Welcome/dashboard content appeared
	if detectSuccessIndicators(after.HTML) && !detectSuccessIndicators(before.HTML) {
		return VerificationResult{
			Success:    true,
			Confidence: 0.80,
			Reason:     "success_indicators_detected",
		}
	}

	// Check 5: Same state - likely failure
	if before.URL == after.URL && similarHTML(before.HTML, after.HTML) {
		return VerificationResult{
			Success:    false,
			Confidence: 0.70,
			Reason:     "no_state_change",
		}
	}

	// Ambiguous - need LLM analysis
	return VerificationResult{
		Success:    false,
		Confidence: 0.50,
		Reason:     "ambiguous_needs_llm",
	}
}

// detectErrorMessage checks for common login error patterns
func detectErrorMessage(html string) bool {
	lower := strings.ToLower(html)

	errorPatterns := []string{
		"invalid password",
		"incorrect password",
		"wrong password",
		"invalid credentials",
		"incorrect credentials",
		"authentication failed",
		"login failed",
		"access denied",
		"invalid username",
		"user not found",
		"bad credentials",
		`class="error"`,
		`class='error'`,
		`id="error"`,
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// urlIndicatesSuccess checks if URL changed to a success indicator
func urlIndicatesSuccess(beforeURL, afterURL string) bool {
	if beforeURL == afterURL {
		return false
	}

	afterLower := strings.ToLower(afterURL)

	successPaths := []string{
		"/dashboard",
		"/admin",
		"/home",
		"/main",
		"/index",
		"/welcome",
		"/console",
		"/panel",
		"/status",
		"/overview",
	}

	for _, path := range successPaths {
		if strings.Contains(afterLower, path) {
			return true
		}
	}

	// Check if moved away from login page
	beforeLower := strings.ToLower(beforeURL)
	loginPaths := []string{"/login", "/signin", "/auth", "/logon"}

	for _, path := range loginPaths {
		if strings.Contains(beforeLower, path) && !strings.Contains(afterLower, path) {
			return true
		}
	}

	return false
}

// hasPasswordField checks if HTML contains a password input
func hasPasswordField(html string) bool {
	return strings.Contains(strings.ToLower(html), `type="password"`) ||
		strings.Contains(strings.ToLower(html), `type='password'`)
}

// detectSuccessIndicators checks for common success page patterns
func detectSuccessIndicators(html string) bool {
	lower := strings.ToLower(html)

	indicators := []string{
		"welcome",
		"logged in",
		"dashboard",
		"logout",
		"sign out",
		"log out",
		"my account",
		"settings",
		"configuration",
		"system status",
	}

	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}

	return false
}

// similarHTML checks if two HTML strings are substantially similar
func similarHTML(a, b string) bool {
	// Simple check: normalize and compare
	normalize := func(s string) string {
		// Remove whitespace variations
		re := regexp.MustCompile(`\s+`)
		return re.ReplaceAllString(strings.ToLower(s), " ")
	}

	na := normalize(a)
	nb := normalize(b)

	// If one is significantly shorter, not similar
	if len(na) < len(nb)/2 || len(nb) < len(na)/2 {
		return false
	}

	// Check if they share significant content
	// This is a simple heuristic - could be improved
	return na == nb || strings.HasPrefix(na, nb[:minInt(len(nb), 500)]) ||
		strings.HasPrefix(nb, na[:minInt(len(na), 500)])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
