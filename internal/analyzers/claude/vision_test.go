// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package claude

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestClient_AnalyzeScreenshot_LoginPage(t *testing.T) {
	// Mock Claude API response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request format
		if r.Header.Get("x-api-key") == "" {
			t.Error("Missing x-api-key header")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Error("Wrong anthropic-version header")
		}

		// Return mock response for login page
		response := map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": `{"is_login_page":true,"confidence":0.95,"application":{"type":"router","vendor":"TP-Link","model":"Archer C7","confidence":0.85}}`,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Model:    "claude-3-haiku-20240307",
		Endpoint: server.URL,
	}

	// Test with dummy screenshot
	screenshot := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes

	analysis, err := client.AnalyzeScreenshot(context.Background(), screenshot)
	if err != nil {
		t.Fatalf("AnalyzeScreenshot failed: %v", err)
	}

	if !analysis.IsLoginPage {
		t.Error("Expected IsLoginPage=true")
	}

	if analysis.Confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9", analysis.Confidence)
	}

	if analysis.Application.Type != "router" {
		t.Errorf("Application.Type = %q, want %q", analysis.Application.Type, "router")
	}

	if analysis.Application.Vendor != "TP-Link" {
		t.Errorf("Application.Vendor = %q, want %q", analysis.Application.Vendor, "TP-Link")
	}
}

func TestClient_AnalyzeScreenshot_NotLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": `{"is_login_page":false,"confidence":0.92,"application":{"type":"unknown","vendor":"","model":"","confidence":0.0}}`,
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

	analysis, err := client.AnalyzeScreenshot(context.Background(), []byte{0x89, 0x50, 0x4E, 0x47})
	if err != nil {
		t.Fatalf("AnalyzeScreenshot failed: %v", err)
	}

	if analysis.IsLoginPage {
		t.Error("Expected IsLoginPage=false")
	}
}

// TestClient_AnalyzeScreenshot_WithFormHints tests backward compatibility with the
// deprecated FormHints field. Remove this test when FormHints is removed from PageAnalysis.
func TestClient_AnalyzeScreenshot_WithFormHints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": `{"is_login_page":true,"confidence":0.88,"application":{"type":"printer","vendor":"HP","model":"LaserJet","confidence":0.75},"form_hints":{"username_selector":"#username","password_selector":"#password","submit_selector":"#login-btn"}}`,
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

	analysis, err := client.AnalyzeScreenshot(context.Background(), []byte{0x89, 0x50, 0x4E, 0x47})
	if err != nil {
		t.Fatalf("AnalyzeScreenshot failed: %v", err)
	}

	if analysis.FormHints == nil {
		t.Fatal("Expected FormHints to be set")
	}

	if analysis.FormHints.UsernameSelector != "#username" {
		t.Errorf("UsernameSelector = %q, want %q", analysis.FormHints.UsernameSelector, "#username")
	}
}

func TestClient_VisionRegistration(t *testing.T) {
	// Vision analyzer should be registered
	factory := brutus.GetAnalyzerFactory("claude-vision")
	if factory == nil {
		t.Fatal("claude-vision analyzer not registered")
	}

	cfg := &brutus.LLMConfig{
		Enabled:  true,
		Provider: "claude-vision",
		APIKey:   "test-key",
	}

	analyzer := factory(cfg)
	if analyzer == nil {
		t.Fatal("Factory returned nil analyzer")
	}
}
