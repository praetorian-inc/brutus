// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package perplexity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestClient_ResearchCredentials_ErrorBodyTruncated(t *testing.T) {
	huge := strings.Repeat("A", 100_000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(huge))
	}))
	defer server.Close()

	client := &Client{APIKey: "test-key", Endpoint: server.URL}
	_, err := client.ResearchCredentials(context.Background(), "router", "TP-Link", "Archer C7")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	prefix := "perplexity api error (status 500)"
	if !strings.Contains(msg, prefix) {
		t.Errorf("error %q missing %q", msg, prefix)
	}
	if len(msg) > maxErrorBody+len(prefix)+10 {
		t.Errorf("error length %d exceeds bound", len(msg))
	}
	if !strings.HasSuffix(msg, "...") {
		t.Errorf("truncated error %q should end with ellipsis", msg)
	}
}

func TestClient_ResearchCredentials_Success(t *testing.T) {
	// Mock Perplexity API response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Header.Get("Authorization") == "" {
			t.Error("Missing Authorization header")
		}

		// Return mock response with credentials
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": `Based on my research, the default credentials for TP-Link Archer C7 router are:

1. Username: admin, Password: admin
2. Username: admin, Password: (empty)
3. Username: admin, Password: 1234

The most common default is admin/admin which is set at factory.`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	creds, err := client.ResearchCredentials(context.Background(), "router", "TP-Link", "Archer C7")
	if err != nil {
		t.Fatalf("ResearchCredentials failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("Expected at least one credential")
	}

	// Check first credential
	found := false
	for _, c := range creds {
		if c.Username == "admin" && c.Password == "admin" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected admin/admin credential")
	}
}

func TestClient_ResearchCredentials_ParsesVariousFormats(t *testing.T) {
	testCases := []struct {
		name     string
		response string
		wantCred Credential
	}{
		{
			name: "colon_format",
			response: `The default credentials are:
- admin:password
- root:root`,
			wantCred: Credential{Username: "admin", Password: "password"},
		},
		{
			name:     "slash_format",
			response: `Default login: admin/admin123`,
			wantCred: Credential{Username: "admin", Password: "admin123"},
		},
		{
			name: "explicit_format",
			response: `Username: administrator
Password: secret`,
			wantCred: Credential{Username: "administrator", Password: "secret"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"choices": []map[string]interface{}{
						{
							"message": map[string]interface{}{
								"content": tc.response,
							},
						},
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client := &Client{
				APIKey:   "test-key",
				Endpoint: server.URL,
			}

			creds, err := client.ResearchCredentials(context.Background(), "router", "Test", "Model")
			if err != nil {
				t.Fatalf("ResearchCredentials failed: %v", err)
			}

			found := false
			for _, c := range creds {
				if c.Username == tc.wantCred.Username && c.Password == tc.wantCred.Password {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected credential %s/%s not found in %v", tc.wantCred.Username, tc.wantCred.Password, creds)
			}
		})
	}
}

func TestClient_Analyze_ReturnsSuggestions(t *testing.T) {
	// Test that Analyze (BannerAnalyzer interface) works
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "Default credentials: admin:admin, root:toor",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{
		Protocol: "browser",
		Target:   "192.168.1.1:80",
		Banner:   `{"application":{"type":"router","vendor":"TP-Link","model":"Archer C7"}}`,
	}

	passwords, err := client.Analyze(context.Background(), banner)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(passwords) == 0 {
		t.Error("Expected password suggestions")
	}
}

func TestClient_Registration(t *testing.T) {
	factory := brutus.GetAnalyzerFactory("perplexity")
	if factory == nil {
		t.Fatal("perplexity analyzer not registered")
	}

	cfg := &brutus.LLMConfig{
		Enabled:  true,
		Provider: "perplexity",
		APIKey:   "test-key",
	}

	analyzer := factory(cfg)
	if analyzer == nil {
		t.Fatal("Factory returned nil analyzer")
	}
}

// TestAnalyzeCredentials_SanitizesBannerOnJSONParseFailure tests that when JSON parsing
// fails, the fallback path sanitizes the banner before passing to researchFromTextWithPairs.
// This is a regression test for the prompt injection vulnerability where unsanitized banner
// text is sent directly to the LLM when JSON parsing fails (line 100 in perplexity.go).
func TestAnalyzeCredentials_SanitizesBannerOnJSONParseFailure(t *testing.T) {
	// Create a test server that captures the request
	var capturedPrompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apiRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if len(req.Messages) > 0 {
				capturedPrompt = req.Messages[0].Content
			}
		}

		// Return minimal valid response
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "admin:admin",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	// Craft a malicious banner with dangerous characters that should be sanitized:
	// - \x00 (null byte)
	// - \x1b[31m (ANSI escape code)
	// - """ (triple quotes for prompt escape)
	maliciousBanner := brutus.BannerInfo{
		Banner: "not valid json\x00with nulls\x1b[31mand ANSI\"\"\"and triple quotes",
	}

	ctx := context.Background()
	_, err := client.AnalyzeCredentials(ctx, maliciousBanner)

	if err != nil {
		t.Fatalf("AnalyzeCredentials failed: %v", err)
	}

	// Verify that the captured prompt does NOT contain dangerous characters
	if capturedPrompt == "" {
		t.Fatal("No prompt captured from API request")
	}

	// Check that dangerous characters were removed
	if containsNullByte(capturedPrompt) {
		t.Error("Prompt contains null byte - sanitization failed")
	}
	if containsANSI(capturedPrompt) {
		t.Error("Prompt contains ANSI escape codes - sanitization failed")
	}
	if containsTripleQuotes(capturedPrompt) {
		t.Error("Prompt contains triple quotes - sanitization failed")
	}

	// Verify the safe parts are still present
	if !contains(capturedPrompt, "not valid json") {
		t.Error("Prompt missing expected content - over-sanitization")
	}
}

// Helper functions for security checks
func containsNullByte(s string) bool {
	for _, c := range s {
		if c == 0 {
			return true
		}
	}
	return false
}

func containsANSI(s string) bool {
	return contains(s, "\x1b[")
}

func containsTripleQuotes(s string) bool {
	return contains(s, `"""`)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || substr == "" ||
		(s != "" && (s[:len(substr)] == substr || contains(s[1:], substr))))
}
