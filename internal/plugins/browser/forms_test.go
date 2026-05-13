// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build chromedp

package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormSubmission_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	// Serve form via HTTP to ensure proper layout computation in headless Chrome
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
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
</html>`)
	}))
	defer srv.Close()

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	b, err := GetBrowser(1)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	tabCtx, release := b.AcquireTab()
	defer release()

	result, err := FillAndSubmitWithNavigate(tabCtx, srv.URL, "admin", "secret123", 15*time.Second)
	if err != nil {
		t.Fatalf("FillAndSubmitWithNavigate failed: %v", err)
	}

	if !strings.Contains(result.AfterHTML, "Submitted: admin:secret123") {
		t.Errorf("Form submission incorrect, AfterHTML does not contain expected result. Got: %s", result.AfterHTML)
	}
}

func TestFormSubmission_EmptyPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if !chromeAvailable() {
		t.Skip("Chrome not available")
	}

	// Serve form via HTTP to ensure proper layout computation in headless Chrome
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
<body>
	<input type="text" id="user">
	<input type="password" id="pass">
	<button id="btn" onclick="document.body.innerHTML='<span id=r>'+document.getElementById('user').value+'</span>'">Go</button>
</body>
</html>`)
	}))
	defer srv.Close()

	resetBrowserSingleton()
	t.Cleanup(resetBrowserSingleton)

	b, err := GetBrowser(1)
	if err != nil {
		t.Fatalf("GetBrowser failed: %v", err)
	}
	defer b.Close()

	tabCtx, release := b.AcquireTab()
	defer release()

	// Test with empty password (common for IoT devices)
	_, err = FillAndSubmitWithNavigate(tabCtx, srv.URL, "admin", "", 15*time.Second)
	if err != nil {
		t.Fatalf("FillAndSubmitWithNavigate with empty password failed: %v", err)
	}
}
