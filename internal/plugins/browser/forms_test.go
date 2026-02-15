// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build chromedp

package browser

import (
	"testing"
	"time"
)

func TestFillAndSubmit_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	b, err := GetBrowser(1)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	tabCtx, release := b.AcquireTab()
	defer release()

	// Navigate to a data URL with a simple form
	html := `data:text/html,
	<html>
	<body>
		<form id="login-form">
			<input type="text" id="username" name="username">
			<input type="password" id="password" name="password">
			<button type="submit" id="submit">Login</button>
		</form>
		<script>
			document.getElementById('login-form').onsubmit = function(e) {
				e.preventDefault();
				document.body.innerHTML = '<h1 id="result">Submitted: ' +
					document.getElementById('username').value + ':' +
					document.getElementById('password').value + '</h1>';
			};
		</script>
	</body>
	</html>`

	err = b.Navigate(tabCtx, html, 5*time.Second)
	if err != nil {
		t.Fatalf("Navigate failed: %v", err)
	}

	fields := &FormFields{
		UsernameSelector: "#username",
		PasswordSelector: "#password",
		SubmitSelector:   "#submit",
	}

	err = FillAndSubmit(tabCtx, fields, "admin", "secret123")
	if err != nil {
		t.Fatalf("FillAndSubmit failed: %v", err)
	}

	// Verify form was submitted by checking for result element
	var resultText string
	err = GetElementText(tabCtx, "#result", &resultText)
	if err != nil {
		t.Fatalf("GetElementText failed: %v", err)
	}

	if resultText != "Submitted: admin:secret123" {
		t.Errorf("Form submission incorrect, got: %s", resultText)
	}
}

func TestFillAndSubmit_EmptyPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	b, err := GetBrowser(1)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	tabCtx, release := b.AcquireTab()
	defer release()

	html := `data:text/html,
	<html>
	<body>
		<input type="text" id="user">
		<input type="password" id="pass">
		<button id="btn" onclick="document.body.innerHTML='<span id=r>'+document.getElementById('user').value+'</span>'">Go</button>
	</body>
	</html>`

	_ = b.Navigate(tabCtx, html, 5*time.Second)

	fields := &FormFields{
		UsernameSelector: "#user",
		PasswordSelector: "#pass",
		SubmitSelector:   "#btn",
	}

	// Test with empty password (common for IoT devices)
	err = FillAndSubmit(tabCtx, fields, "admin", "")
	if err != nil {
		t.Fatalf("FillAndSubmit with empty password failed: %v", err)
	}
}
