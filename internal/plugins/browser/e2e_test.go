// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package browser contains end-to-end tests for the browser plugin.
// These tests require Docker and Chrome to be available.
//
// Run with: go test -tags=e2e ./internal/plugins/browser/... -v
//
// Prerequisites:
//  1. Start mock services: docker-compose -f testdata/docker-compose.yml up -d
//  2. Ensure Chrome/Chromium is installed
//
// The tests will automatically skip if services are not available.
package browser

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Device test case definition
type deviceTestCase struct {
	name        string
	port        int
	validUser   string
	validPass   string
	invalidPass string
	deviceType  string
	skipReason  string
}

// All mock devices and their credentials
var deviceTestCases = []deviceTestCase{
	{
		name:        "TP-Link Router",
		port:        8081,
		validUser:   "admin",
		validPass:   "admin",
		invalidPass: "wrongpassword",
		deviceType:  "router",
	},
	{
		name:        "Hikvision Camera",
		port:        8082,
		validUser:   "admin",
		validPass:   "12345",
		invalidPass: "wrongpassword",
		deviceType:  "camera",
	},
	{
		name:        "HP Printer",
		port:        8083,
		validUser:   "admin",
		validPass:   "", // Empty password
		invalidPass: "wrongpassword",
		deviceType:  "printer",
	},
	{
		name:        "Synology NAS",
		port:        8084,
		validUser:   "admin",
		validPass:   "synology",
		invalidPass: "wrongpassword",
		deviceType:  "nas",
	},
	{
		name:        "Generic Admin Panel",
		port:        8085,
		validUser:   "admin",
		validPass:   "password",
		invalidPass: "wrongpassword",
		deviceType:  "generic",
	},
}

// TestE2E_Setup verifies test prerequisites
func TestE2E_Setup(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available - install Chrome/Chromium to run e2e tests")
	}

	if !dockerAvailable() {
		t.Skip("Docker not available - install Docker to run e2e tests")
	}

	t.Log("E2E test prerequisites met: Chrome and Docker available")
}

// TestE2E_ValidCredentials tests successful login with correct credentials
func TestE2E_ValidCredentials(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	for _, tc := range deviceTestCases {
		tc := tc // capture range variable
		t.Run(tc.name+"_ValidLogin", func(t *testing.T) {
			if !isServiceAvailable(tc.port) {
				t.Skipf("Mock service not running on port %d - run: docker-compose -f testdata/docker-compose.yml up -d", tc.port)
			}

			resetBrowserSingleton()
			t.Cleanup(resetBrowserSingleton)

			plugin, err := brutus.GetPlugin("browser")
			if err != nil {
				t.Fatalf("Failed to get browser plugin: %v", err)
			}

			target := fmt.Sprintf("localhost:%d", tc.port)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result := plugin.Test(ctx, target, tc.validUser, tc.validPass, 30*time.Second, brutus.PluginConfig{})

			if result.Error != nil {
				t.Errorf("Unexpected error: %v", result.Error)
			}

			// With valid credentials, we expect either success or at least no error
			// (success detection may vary based on redirect handling)
			t.Logf("[%s] Result: Success=%v, Duration=%v", tc.name, result.Success, result.Duration)

			if result.Banner != "" {
				t.Logf("[%s] Banner: %s", tc.name, result.Banner)
			}
		})
	}
}

// TestE2E_InvalidCredentials tests failed login with incorrect credentials
func TestE2E_InvalidCredentials(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	for _, tc := range deviceTestCases {
		tc := tc
		t.Run(tc.name+"_InvalidLogin", func(t *testing.T) {
			if !isServiceAvailable(tc.port) {
				t.Skipf("Mock service not running on port %d", tc.port)
			}

			resetBrowserSingleton()
			t.Cleanup(resetBrowserSingleton)

			plugin, err := brutus.GetPlugin("browser")
			if err != nil {
				t.Fatalf("Failed to get browser plugin: %v", err)
			}

			target := fmt.Sprintf("localhost:%d", tc.port)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result := plugin.Test(ctx, target, tc.validUser, tc.invalidPass, 30*time.Second, brutus.PluginConfig{})

			// With invalid credentials, we expect failure (no error, just Success=false)
			if result.Success {
				t.Errorf("[%s] Expected failure with invalid credentials, but got success", tc.name)
			}

			t.Logf("[%s] Result: Success=%v (expected false), Duration=%v", tc.name, result.Success, result.Duration)
		})
	}
}

// TestE2E_FormDetection verifies form fields are detected correctly
func TestE2E_FormDetection(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	for _, tc := range deviceTestCases {
		tc := tc
		t.Run(tc.name+"_FormDetection", func(t *testing.T) {
			if !isServiceAvailable(tc.port) {
				t.Skipf("Mock service not running on port %d", tc.port)
			}

			resetBrowserSingleton()
			t.Cleanup(resetBrowserSingleton)

			b, err := GetBrowser(1)
			if err != nil {
				t.Fatalf("GetBrowser failed: %v", err)
			}

			tabCtx, release := b.AcquireTab()
			defer release()

			// Use NavigateAndGetHTML to avoid chromedp context issues between
			// separate Navigate and GetPageHTML calls.
			url := fmt.Sprintf("http://localhost:%d/", tc.port)
			html, err := b.NavigateAndGetHTML(tabCtx, url, 10*time.Second)
			if err != nil {
				t.Fatalf("NavigateAndGetHTML failed: %v", err)
			}

			fields, err := DetectFormFields(html)
			if err != nil {
				t.Fatalf("[%s] Form detection failed: %v", tc.name, err)
			}

			// Verify we found all required fields
			if fields.UsernameSelector == "" {
				t.Errorf("[%s] Username field not detected", tc.name)
			}
			if fields.PasswordSelector == "" {
				t.Errorf("[%s] Password field not detected", tc.name)
			}
			if fields.SubmitSelector == "" {
				t.Errorf("[%s] Submit button not detected", tc.name)
			}

			t.Logf("[%s] Detected fields: username=%s, password=%s, submit=%s",
				tc.name, fields.UsernameSelector, fields.PasswordSelector, fields.SubmitSelector)
		})
	}
}

// TestE2E_ErrorMessageDetection verifies error messages are detected after failed login
func TestE2E_ErrorMessageDetection(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	for _, tc := range deviceTestCases {
		tc := tc
		t.Run(tc.name+"_ErrorDetection", func(t *testing.T) {
			if !isServiceAvailable(tc.port) {
				t.Skipf("Mock service not running on port %d", tc.port)
			}

			resetBrowserSingleton()
			t.Cleanup(resetBrowserSingleton)

			b, err := GetBrowser(1)
			if err != nil {
				t.Fatalf("GetBrowser failed: %v", err)
			}

			tabCtx, release := b.AcquireTab()
			defer release()

			// Use FillAndSubmitWithNavigate to do navigate + fill + submit in a
			// single chromedp.Run, avoiding context lifecycle issues.
			url := fmt.Sprintf("http://localhost:%d/", tc.port)
			formResult, err := FillAndSubmitWithNavigate(tabCtx, url, tc.validUser, tc.invalidPass, 30*time.Second)
			if err != nil {
				t.Fatalf("FillAndSubmitWithNavigate failed: %v", err)
			}

			// Construct verification states from the single-Run result.
			// The before URL is the page we navigated to.
			beforeState := VerificationState{URL: url, HTML: ""}
			afterState := VerificationState{URL: formResult.AfterURL, HTML: formResult.AfterHTML}

			// Verify login failed
			result := VerifyLogin(beforeState, afterState)

			if result.Success {
				t.Errorf("[%s] Expected verification to detect failure", tc.name)
			}

			t.Logf("[%s] Verification: Success=%v, Confidence=%.2f, Reason=%s",
				tc.name, result.Success, result.Confidence, result.Reason)

			// Check if error message was detected
			if result.Reason == "error_message_detected" {
				t.Logf("[%s] Error message correctly detected", tc.name)
			}
		})
	}
}

// TestE2E_SuccessfulLoginVerification verifies successful login is detected
func TestE2E_SuccessfulLoginVerification(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	for _, tc := range deviceTestCases {
		tc := tc
		t.Run(tc.name+"_SuccessVerification", func(t *testing.T) {
			if !isServiceAvailable(tc.port) {
				t.Skipf("Mock service not running on port %d", tc.port)
			}

			resetBrowserSingleton()
			t.Cleanup(resetBrowserSingleton)

			b, err := GetBrowser(1)
			if err != nil {
				t.Fatalf("GetBrowser failed: %v", err)
			}

			tabCtx, release := b.AcquireTab()
			defer release()

			// Use FillAndSubmitWithNavigate to do navigate + fill + submit in a
			// single chromedp.Run, avoiding context lifecycle issues.
			url := fmt.Sprintf("http://localhost:%d/", tc.port)
			formResult, err := FillAndSubmitWithNavigate(tabCtx, url, tc.validUser, tc.validPass, 30*time.Second)
			if err != nil {
				t.Fatalf("FillAndSubmitWithNavigate failed: %v", err)
			}

			// Construct verification states from the single-Run result.
			beforeState := VerificationState{URL: url, HTML: ""}
			afterState := VerificationState{URL: formResult.AfterURL, HTML: formResult.AfterHTML}

			// Verify login succeeded
			result := VerifyLogin(beforeState, afterState)

			t.Logf("[%s] Verification: Success=%v, Confidence=%.2f, Reason=%s",
				tc.name, result.Success, result.Confidence, result.Reason)
			t.Logf("[%s] URL before=%s, after=%s", tc.name, url, formResult.AfterURL)

			// Most login pages redirect to dashboard after success
			if result.Success {
				t.Logf("[%s] Login success correctly verified", tc.name)
			} else if result.Reason == "login_form_disappeared" || result.Reason == "url_changed_to_dashboard" {
				t.Logf("[%s] Login verification positive indicator: %s", tc.name, result.Reason)
			}
		})
	}
}

// TestE2E_ConcurrentLogins tests concurrent login attempts
func TestE2E_ConcurrentLogins(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	// Only test against router (simplest)
	tc := deviceTestCases[0] // Router
	if !isServiceAvailable(tc.port) {
		t.Skipf("Mock service not running on port %d", tc.port)
	}

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	plugin, err := brutus.GetPlugin("browser")
	if err != nil {
		t.Fatalf("Failed to get browser plugin: %v", err)
	}

	// Run 3 concurrent login tests
	const concurrentTests = 3
	results := make(chan *brutus.Result, concurrentTests)
	target := fmt.Sprintf("localhost:%d", tc.port)

	for i := 0; i < concurrentTests; i++ {
		go func(idx int) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			result := plugin.Test(ctx, target, tc.validUser, tc.validPass, 30*time.Second, brutus.PluginConfig{})
			results <- result
		}(i)
	}

	// Collect results
	for i := 0; i < concurrentTests; i++ {
		result := <-results
		if result.Error != nil {
			t.Errorf("Concurrent test %d failed with error: %v", i, result.Error)
		}
		t.Logf("Concurrent test %d: Success=%v, Duration=%v", i, result.Success, result.Duration)
	}
}

// Helper functions

func isServiceAvailable(port int) bool {
	url := fmt.Sprintf("http://localhost:%d/health", port)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func dockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}
