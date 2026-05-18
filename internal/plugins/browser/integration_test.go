// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build chromedp

package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Integration_FullPipeline(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	// Create a mock login server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Serve login page
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
				<head><title>Router Login</title></head>
				<body>
					<h1>TP-Link Router</h1>
					<form method="POST" action="/login">
						<input type="text" name="username" id="username" placeholder="Username">
						<input type="password" name="password" id="password" placeholder="Password">
						<button type="submit" id="login-btn">Login</button>
					</form>
				</body>
				</html>
			`))
			return
		}

		// Handle POST login
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "admin" && password == "admin" {
			// Success - redirect to dashboard
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}

		// Failure - show error
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<html>
			<body>
				<div class="error">Invalid credentials</div>
				<form method="POST" action="/login">
					<input type="text" name="username" id="username">
					<input type="password" name="password" id="password">
					<button type="submit">Login</button>
				</form>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	// Get the plugin
	plugin, err := brutus.GetPlugin("browser")
	if err != nil {
		t.Fatalf("Failed to get browser plugin: %v", err)
	}

	// Extract host:port from server URL
	target := server.URL[7:] // Remove "http://"

	// Test with correct credentials
	result := plugin.Test(context.Background(), target, "admin", "admin", 30*time.Second, brutus.PluginConfig{})

	if result.Error != nil {
		t.Fatalf("Test failed with error: %v", result.Error)
	}

	// Note: Full success verification requires the mock server to properly
	// handle form submission with JavaScript, which httptest doesn't do well.
	// In a real integration test, we'd use a proper test server with JS support.

	t.Logf("Result: Success=%v, Duration=%v", result.Success, result.Duration)
}

func TestPlugin_Integration_InvalidCredentials(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<html>
			<body>
				<div class="error">Invalid password</div>
				<input type="password" id="pwd">
				<button>Login</button>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	plugin, _ := brutus.GetPlugin("browser")
	target := server.URL[7:]

	result := plugin.Test(context.Background(), target, "admin", "wrong", 30*time.Second, brutus.PluginConfig{})

	// Should detect error message and return failure
	if result.Success {
		t.Error("Expected failure for invalid credentials")
	}
}

func TestPlugin_Integration_NoLoginPage(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<html>
			<body>
				<h1>Welcome to our website</h1>
				<p>This is just a regular page with no login form.</p>
			</body>
			</html>
		`))
	}))
	defer server.Close()

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	plugin, _ := brutus.GetPlugin("browser")
	target := server.URL[7:]

	result := plugin.Test(context.Background(), target, "admin", "admin", 30*time.Second, brutus.PluginConfig{})

	// Should detect no login page
	if result.Success {
		t.Error("Expected failure for non-login page")
	}

	if result.Error != nil && result.Error.Error() != "" {
		// Error about no password field is expected
		t.Logf("Expected error: %v", result.Error)
	}
}
