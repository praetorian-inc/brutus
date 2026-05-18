// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"fmt"
	"regexp"
	"strings"
)

// FormFields contains CSS selectors for login form elements
type FormFields struct {
	UsernameSelector string
	PasswordSelector string
	SubmitSelector   string
}

// DetectFormFields analyzes HTML to find login form field selectors
func DetectFormFields(html string) (*FormFields, error) {
	fields := &FormFields{}

	// Detect password field first (most reliable indicator)
	fields.PasswordSelector = detectPasswordField(html)
	if fields.PasswordSelector == "" {
		return fields, fmt.Errorf("no password field detected")
	}

	// Detect username field
	fields.UsernameSelector = detectUsernameField(html)

	// Detect submit button
	fields.SubmitSelector = detectSubmitButton(html)

	return fields, nil
}

// detectPasswordField finds the password input selector
func detectPasswordField(html string) string {
	// Pattern: input with type="password"
	patterns := []struct {
		regex    string
		selector func(matches []string) string
	}{
		// input type="password" with id
		{
			regex: `<input[^>]*type=["']password["'][^>]*id=["']([^"']+)["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return "#" + m[1]
				}
				return ""
			},
		},
		// input type="password" with id (reverse order)
		{
			regex: `<input[^>]*id=["']([^"']+)["'][^>]*type=["']password["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return "#" + m[1]
				}
				return ""
			},
		},
		// input type="password" with name
		{
			regex: `<input[^>]*type=["']password["'][^>]*name=["']([^"']+)["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return `input[name="` + m[1] + `"]`
				}
				return ""
			},
		},
		// input type="password" with name (reverse order)
		{
			regex: `<input[^>]*name=["']([^"']+)["'][^>]*type=["']password["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return `input[name="` + m[1] + `"]`
				}
				return ""
			},
		},
		// Generic type="password"
		{
			regex:    `<input[^>]*type=["']password["']`,
			selector: func(m []string) string { return `input[type="password"]` },
		},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(`(?i)` + p.regex)
		matches := re.FindStringSubmatch(html)
		if matches != nil {
			sel := p.selector(matches)
			if sel != "" {
				return sel
			}
		}
	}

	return ""
}

// detectUsernameField finds the username/login input selector
func detectUsernameField(html string) string {
	// Common username field indicators
	indicators := []string{
		"username", "user", "login", "email", "userid", "account",
		"uname", "name", "usr", "uid",
		"signin", "logon", "auth",
	}

	// Try to find input with id containing indicator
	for _, ind := range indicators {
		pattern := fmt.Sprintf(`(?i)<input[^>]*id=["']([^"']*%s[^"']*)["']`, ind)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			return "#" + matches[1]
		}
	}

	// Try to find input with name containing indicator
	for _, ind := range indicators {
		pattern := fmt.Sprintf(`(?i)<input[^>]*name=["']([^"']*%s[^"']*)["']`, ind)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			return `input[name="` + matches[1] + `"]`
		}
	}

	// Try to find input with placeholder containing indicator
	for _, ind := range indicators {
		pattern := fmt.Sprintf(`(?i)<input[^>]*placeholder=["']([^"']*%s[^"']*)["']`, ind)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			return `input[placeholder="` + matches[1] + `"]`
		}
	}

	// Try to find input with class containing indicator
	for _, ind := range indicators {
		pattern := fmt.Sprintf(`(?i)<input[^>]*class=["'][^"']*(%s[^"'\s]*)[^"']*["']`, ind)
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			return "." + matches[1]
		}
	}

	// Fallback: find text input before password field
	// This is a simple heuristic - look for type="text" input
	re := regexp.MustCompile(`(?i)<input[^>]*type=["']text["'][^>]*id=["']([^"']+)["']`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return "#" + matches[1]
	}

	re = regexp.MustCompile(`(?i)<input[^>]*type=["']text["'][^>]*name=["']([^"']+)["']`)
	matches = re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return `input[name="` + matches[1] + `"]`
	}

	// Last resort: first text input
	re = regexp.MustCompile(`(?i)<input[^>]*type=["']text["']`)
	if re.MatchString(html) {
		return `input[type="text"]`
	}

	return ""
}

// detectSubmitButton finds the submit button selector
func detectSubmitButton(html string) string {
	// Priority 1: button/input with type="submit" and id
	patterns := []struct {
		regex    string
		selector func(matches []string) string
	}{
		// button type="submit" with id
		{
			regex: `(?i)<button[^>]*type=["']submit["'][^>]*id=["']([^"']+)["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return "#" + m[1]
				}
				return ""
			},
		},
		// button with id containing login/submit
		{
			regex: `(?i)<button[^>]*id=["']([^"']*(?:login|submit|signin)[^"']*)["']`,
			selector: func(m []string) string {
				if len(m) > 1 {
					return "#" + m[1]
				}
				return ""
			},
		},
		// input type="submit"
		{
			regex:    `(?i)<input[^>]*type=["']submit["']`,
			selector: func(m []string) string { return `input[type="submit"]` },
		},
		// button type="submit"
		{
			regex:    `(?i)<button[^>]*type=["']submit["']`,
			selector: func(m []string) string { return `button[type="submit"]` },
		},
		// button with login/signin text
		{
			regex:    `(?i)<button[^>]*>(?:[^<]*(?:login|sign\s*in|submit)[^<]*)</button>`,
			selector: func(m []string) string { return `button` },
		},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.regex)
		matches := re.FindStringSubmatch(html)
		if matches != nil {
			sel := p.selector(matches)
			if sel != "" {
				return sel
			}
		}
	}

	// Fallback: any button
	if strings.Contains(strings.ToLower(html), "<button") {
		return "button"
	}

	return ""
}
