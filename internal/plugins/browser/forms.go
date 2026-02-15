// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// FormSubmitResult contains the result of form submission including post-login state
type FormSubmitResult struct {
	Success     bool
	AfterURL    string
	AfterHTML   string
	HasPassword bool
	Error       string
}

// FillAndSubmitWithNavigate navigates to a URL and fills the login form in a single operation.
// This avoids chromedp context issues that occur when doing multiple separate chromedp.Run calls.
// Returns the post-login state for verification.
func FillAndSubmitWithNavigate(tabCtx context.Context, url, username, password string, timeout time.Duration) (*FormSubmitResult, error) {
	ctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	// JavaScript to fill the form
	fillJS := fmt.Sprintf(`
		(function(username, password) {
			// Find password field first (most reliable anchor)
			const pwd = document.querySelector('input[type="password"]');
			if (!pwd) return 'error: no password field found';

			// Find the form containing the password field
			const form = pwd.closest('form');

			// Find username input: text/email input in same form, or before password
			let usernameInput = null;
			if (form) {
				const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
				for (const inp of inputs) {
					if (inp.offsetParent !== null || inp.offsetWidth > 0) {
						usernameInput = inp;
						break;
					}
				}
			}

			// Fallback: find any visible text input on page
			if (!usernameInput) {
				const allInputs = document.querySelectorAll('input[type="text"], input[type="email"]');
				for (const inp of allInputs) {
					if (inp.offsetParent !== null || inp.offsetWidth > 0) {
						usernameInput = inp;
						break;
					}
				}
			}

			// Fill username
			if (usernameInput) {
				usernameInput.focus();
				usernameInput.value = username;
				usernameInput.dispatchEvent(new Event('input', { bubbles: true }));
				usernameInput.dispatchEvent(new Event('change', { bubbles: true }));
			}

			// Fill password
			pwd.focus();
			pwd.value = password;
			pwd.dispatchEvent(new Event('input', { bubbles: true }));
			pwd.dispatchEvent(new Event('change', { bubbles: true }));

			// Find and click submit button
			let submitBtn = null;
			if (form) {
				submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button');
			}
			if (!submitBtn) {
				submitBtn = document.querySelector('button[type="submit"], input[type="submit"]');
			}
			if (!submitBtn) {
				submitBtn = document.querySelector('button');
			}

			if (submitBtn) {
				submitBtn.click();
				return 'ok';
			}

			if (form) {
				form.submit();
				return 'ok: form.submit()';
			}

			return 'error: no submit button found';
		})(%q, %q)
	`, username, password)

	// JavaScript to check post-login state
	checkJS := `
		(function() {
			return JSON.stringify({
				url: window.location.href,
				hasPassword: !!document.querySelector('input[type="password"]'),
				html: document.documentElement.outerHTML.substring(0, 5000)
			});
		})()
	`

	var fillResult string
	var checkResult string

	// All operations in ONE chromedp.Run call to avoid context issues
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(1*time.Second), // Wait for page load
		chromedp.Evaluate(fillJS, &fillResult),
		chromedp.Sleep(2*time.Second), // Wait for form submission + redirect
		chromedp.Evaluate(checkJS, &checkResult),
	)

	if err != nil {
		return nil, fmt.Errorf("form fill failed: %w", err)
	}

	if len(fillResult) > 6 && fillResult[:6] == "error:" {
		return nil, fmt.Errorf("form fill failed: %s", fillResult)
	}

	// Parse check result
	var state struct {
		URL         string `json:"url"`
		HasPassword bool   `json:"hasPassword"`
		HTML        string `json:"html"`
	}
	if err := json.Unmarshal([]byte(checkResult), &state); err != nil {
		return nil, fmt.Errorf("failed to parse post-login state: %w", err)
	}

	return &FormSubmitResult{
		AfterURL:    state.URL,
		AfterHTML:   state.HTML,
		HasPassword: state.HasPassword,
	}, nil
}

// FillAndSubmit fills form fields and clicks submit using JavaScript for reliability
// Deprecated: Use FillAndSubmitWithNavigate instead to avoid context issues
func FillAndSubmit(tabCtx context.Context, fields *FormFields, username, password string) error {
	ctx, cancel := context.WithTimeout(tabCtx, 15*time.Second)
	defer cancel()

	jsCode := fmt.Sprintf(`
		(function(username, password) {
			const pwd = document.querySelector('input[type="password"]');
			if (!pwd) return 'error: no password field found';
			const form = pwd.closest('form');
			let usernameInput = null;
			if (form) {
				const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
				for (const inp of inputs) {
					if (inp.offsetParent !== null || inp.offsetWidth > 0) {
						usernameInput = inp;
						break;
					}
				}
			}
			if (!usernameInput) {
				const allInputs = document.querySelectorAll('input[type="text"], input[type="email"]');
				for (const inp of allInputs) {
					if (inp.offsetParent !== null || inp.offsetWidth > 0) {
						usernameInput = inp;
						break;
					}
				}
			}
			if (usernameInput) {
				usernameInput.focus();
				usernameInput.value = username;
				usernameInput.dispatchEvent(new Event('input', { bubbles: true }));
				usernameInput.dispatchEvent(new Event('change', { bubbles: true }));
			}
			pwd.focus();
			pwd.value = password;
			pwd.dispatchEvent(new Event('input', { bubbles: true }));
			pwd.dispatchEvent(new Event('change', { bubbles: true }));
			let submitBtn = form ? form.querySelector('button[type="submit"], input[type="submit"], button') : null;
			if (!submitBtn) submitBtn = document.querySelector('button[type="submit"], input[type="submit"]');
			if (!submitBtn) submitBtn = document.querySelector('button');
			if (submitBtn) { submitBtn.click(); return 'ok'; }
			if (form) { form.submit(); return 'ok: form.submit()'; }
			return 'error: no submit button found';
		})(%q, %q)
	`, username, password)

	var result string
	err := chromedp.Run(ctx,
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(jsCode, &result),
		chromedp.Sleep(1*time.Second),
	)

	if err != nil {
		return fmt.Errorf("form fill failed: %w", err)
	}

	if len(result) > 6 && result[:6] == "error:" {
		return fmt.Errorf("form fill failed: %s", result)
	}

	return nil
}

// GetElementText retrieves text content of an element
func GetElementText(tabCtx context.Context, selector string, result *string) error {
	ctx, cancel := context.WithTimeout(tabCtx, 5*time.Second)
	defer cancel()

	return chromedp.Run(ctx,
		chromedp.Text(selector, result, chromedp.ByQuery),
	)
}

// GetPageHTML retrieves the full page HTML
func GetPageHTML(tabCtx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(tabCtx, 5*time.Second)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	return html, err
}

// GetCurrentURL retrieves the current page URL
func GetCurrentURL(tabCtx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(tabCtx, 5*time.Second)
	defer cancel()

	var url string
	err := chromedp.Run(ctx,
		chromedp.Location(&url),
	)
	return url, err
}
