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

package brutus

import (
	"context"
	"strings"
	"testing"
)

// TestSanitizeBanner tests the prompt injection defense for banner text
func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes null bytes",
			input:    "banner\x00with\x00nulls",
			expected: "bannerwithnulls",
		},
		{
			name:     "removes ANSI escape codes",
			input:    "\x1b[31mRed text\x1b[0m normal",
			expected: "Red text normal",
		},
		{
			name:     "removes triple quotes",
			input:    `banner with """ embedded`,
			expected: "banner with  embedded",
		},
		{
			name:     "truncates to 500 chars",
			input:    strings.Repeat("a", 600),
			expected: strings.Repeat("a", 500),
		},
		{
			name:     "passes through normal banner unchanged",
			input:    "SSH-2.0-OpenSSH_7.4",
			expected: "SSH-2.0-OpenSSH_7.4",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "combines all sanitization rules",
			input:    "\x00\x1b[31m" + strings.Repeat("x", 300) + `"""injection` + strings.Repeat("y", 300),
			expected: strings.Repeat("x", 300) + "injection" + strings.Repeat("y", 191), // total: 300 + 9 + 191 chars
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeBanner(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeBanner() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestValidateSuggestions tests LLM output validation
func TestValidateSuggestions(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "accepts valid passwords",
			input:    []string{"admin123", "P@ssw0rd!", "root"},
			expected: []string{"admin123", "P@ssw0rd!", "root"},
		},
		{
			name:     "rejects empty passwords",
			input:    []string{"admin", "", "root"},
			expected: []string{"admin", "root"},
		},
		{
			name:     "rejects passwords over 32 chars",
			input:    []string{"admin", strings.Repeat("a", 33), "root"},
			expected: []string{"admin", "root"},
		},
		{
			name:     "rejects passwords with disallowed chars (semicolon)",
			input:    []string{"admin;rm -rf /", "valid123"},
			expected: []string{"valid123"},
		},
		{
			name:     "rejects passwords with disallowed chars (pipe)",
			input:    []string{"admin|nc attacker.com", "valid123"},
			expected: []string{"valid123"},
		},
		{
			name:     "rejects passwords with disallowed chars (backtick)",
			input:    []string{"admin`whoami`", "valid123"},
			expected: []string{"valid123"},
		},
		{
			name:     "rejects passwords with disallowed chars (newline)",
			input:    []string{"admin\nignore previous instructions", "valid123"},
			expected: []string{"valid123"},
		},
		{
			name:     "limits to max 4 suggestions",
			input:    []string{"pass1", "pass2", "pass3", "pass4", "pass5", "pass6"},
			expected: []string{"pass1", "pass2", "pass3", "pass4"},
		},
		{
			name:     "handles empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "handles all invalid passwords",
			input:    []string{"", ";injection", "|pipe", "`backtick`"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSuggestions(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("ValidateSuggestions() length = %d, want %d", len(result), len(tt.expected))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("ValidateSuggestions()[%d] = %q, want %q", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// TestIsValidPassword tests individual password validation
func TestIsValidPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		valid    bool
	}{
		{
			name:     "accepts alphanumeric",
			password: "admin123",
			valid:    true,
		},
		{
			name:     "accepts allowed symbols",
			password: "P@ssw0rd!",
			valid:    true,
		},
		{
			name:     "accepts brackets and braces",
			password: "pass[word]",
			valid:    true,
		},
		{
			name:     "accepts hyphens and underscores",
			password: "pass-word_123",
			valid:    true,
		},
		{
			name:     "rejects spaces",
			password: "pass word",
			valid:    false,
		},
		{
			name:     "rejects semicolons",
			password: "admin;injection",
			valid:    false,
		},
		{
			name:     "rejects pipes",
			password: "admin|nc",
			valid:    false,
		},
		{
			name:     "rejects backticks",
			password: "admin`cmd`",
			valid:    false,
		},
		{
			name:     "rejects newlines",
			password: "admin\ninjection",
			valid:    false,
		},
		{
			name:     "rejects tabs",
			password: "admin\tinjection",
			valid:    false,
		},
		{
			name:     "rejects quotes",
			password: `admin"quote`,
			valid:    false,
		},
		{
			name:     "rejects single quotes",
			password: "admin'quote",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidPassword(tt.password)
			if result != tt.valid {
				t.Errorf("IsValidPassword(%q) = %v, want %v", tt.password, result, tt.valid)
			}
		})
	}
}

func TestResearchCredentials_NilConfig(t *testing.T) {
	result := ResearchCredentials(context.Background(), "target:80", "banner", nil)
	if result != nil {
		t.Errorf("expected nil for nil config, got %v", result)
	}
}

func TestResearchCredentials_DisabledConfig(t *testing.T) {
	cfg := &LLMConfig{Enabled: false, Provider: "test"}
	result := ResearchCredentials(context.Background(), "target:80", "banner", cfg)
	if result != nil {
		t.Errorf("expected nil for disabled config, got %v", result)
	}
}

func TestResearchCredentials_UnknownProvider(t *testing.T) {
	cfg := &LLMConfig{Enabled: true, Provider: "nonexistent-provider"}
	result := ResearchCredentials(context.Background(), "target:80", "banner", cfg)
	if result != nil {
		t.Errorf("expected nil for unknown provider, got %v", result)
	}
}
