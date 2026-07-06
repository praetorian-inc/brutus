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

//go:build integration

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/analyzers/claude"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// TestHTTPWithLLM_EndToEnd_Grafana tests the complete flow:
// 1. HTTP server simulates Grafana with Basic Auth
// 2. Capture banner from HTTP response
// 3. Send to LLM for credential suggestions
// 4. Verify LLM suggests appropriate credentials
// 5. Test those credentials against the server
func TestHTTPWithLLM_EndToEnd_Grafana(t *testing.T) {
	// Skip if no API key available
	apiKey, provider := getLLMAPIKey()
	if apiKey == "" {
		t.Skip("No LLM API key available (set ANTHROPIC_API_KEY)")
	}

	t.Logf("Using LLM provider: %s", provider)

	// Create Grafana-like server with Basic Auth
	// Grafana default is admin:admin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "admin" {
			w.Header().Set("Server", "Grafana")
			w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
			w.Header().Set("X-Grafana-Version", "10.0.0")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Grafana</title></head>
<body>
<h1>Grafana Login</h1>
<p>Please authenticate to access Grafana dashboards.</p>
</body>
</html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message": "Welcome to Grafana"}`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")
	ctx := context.Background()

	// Step 1: Capture banner using HTTP plugin (empty creds)
	plugin := &Plugin{Path: "/", UseHTTPS: false}
	bannerResult := plugin.Test(ctx, target, "", "", 10*time.Second, brutus.PluginConfig{})

	require.NotNil(t, bannerResult)
	require.NotEmpty(t, bannerResult.Banner, "Should capture HTTP banner")

	t.Logf("Captured banner:\n%s", bannerResult.Banner)

	// Verify banner contains Grafana identifiers
	assert.Contains(t, bannerResult.Banner, "Grafana", "Banner should identify Grafana")

	// Step 2: Send banner to LLM for analysis
	analyzer := createAnalyzer(provider, apiKey)
	require.NotNil(t, analyzer, "Should create analyzer")

	bannerInfo := brutus.BannerInfo{
		Protocol: "http",
		Target:   target,
		Banner:   bannerResult.Banner,
	}

	suggestions, err := analyzer.Analyze(ctx, bannerInfo)
	require.NoError(t, err, "LLM analysis should succeed")
	require.NotEmpty(t, suggestions, "LLM should return suggestions")

	t.Logf("LLM suggested passwords: %v", suggestions)

	// Step 3: Check if LLM suggested "admin" (Grafana default)
	foundAdmin := false
	for _, pwd := range suggestions {
		if pwd == "admin" {
			foundAdmin = true
			break
		}
	}
	assert.True(t, foundAdmin, "LLM should suggest 'admin' for Grafana (default password)")

	// Step 4: Test LLM suggestions against the server
	var successResult *brutus.Result
	for _, suggestedPwd := range suggestions {
		result := plugin.Test(ctx, target, "admin", suggestedPwd, 5*time.Second, brutus.PluginConfig{})
		t.Logf("Testing admin:%s -> Success=%v", suggestedPwd, result.Success)
		if result.Success {
			successResult = result
			break
		}
	}

	require.NotNil(t, successResult, "At least one LLM suggestion should succeed")
	assert.True(t, successResult.Success, "Should authenticate successfully")
	assert.Equal(t, "admin", successResult.Username)
	assert.Equal(t, "admin", successResult.Password)
}

// TestHTTPWithLLM_EndToEnd_Jenkins tests Jenkins default credential detection
func TestHTTPWithLLM_EndToEnd_Jenkins(t *testing.T) {
	apiKey, provider := getLLMAPIKey()
	if apiKey == "" {
		t.Skip("No LLM API key available")
	}

	t.Logf("Using LLM provider: %s", provider)

	// Create Jenkins-like server
	// Jenkins has various defaults, commonly admin:admin or no password initially
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		// Jenkins common defaults
		validCreds := (username == "admin" && password == "admin") ||
			(username == "admin" && password == "password") ||
			(username == "jenkins" && password == "jenkins")

		if !ok || !validCreds {
			w.Header().Set("Server", "Jetty(10.0.13)")
			w.Header().Set("X-Jenkins", "2.426.1")
			w.Header().Set("X-Hudson", "1.395")
			w.Header().Set("WWW-Authenticate", `Basic realm="Jenkins"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<html>
<head><title>Jenkins [Jenkins]</title></head>
<body>
<div id="jenkins">
<h1>Authentication required</h1>
<p>You are authenticated as: anonymous</p>
</div>
</body>
</html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`Jenkins Dashboard`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")
	ctx := context.Background()

	// Capture banner
	plugin := &Plugin{Path: "/", UseHTTPS: false}
	bannerResult := plugin.Test(ctx, target, "", "", 10*time.Second, brutus.PluginConfig{})

	require.NotNil(t, bannerResult)
	t.Logf("Captured banner:\n%s", bannerResult.Banner)

	assert.Contains(t, bannerResult.Banner, "Jenkins", "Banner should identify Jenkins")

	// Get LLM suggestions
	analyzer := createAnalyzer(provider, apiKey)
	bannerInfo := brutus.BannerInfo{
		Protocol: "http",
		Target:   target,
		Banner:   bannerResult.Banner,
	}

	suggestions, err := analyzer.Analyze(ctx, bannerInfo)
	require.NoError(t, err)
	require.NotEmpty(t, suggestions)

	t.Logf("LLM suggested passwords: %v", suggestions)

	// Test suggestions
	var successResult *brutus.Result
	for _, suggestedPwd := range suggestions {
		// Test with common usernames
		for _, user := range []string{"admin", "jenkins"} {
			result := plugin.Test(ctx, target, user, suggestedPwd, 5*time.Second, brutus.PluginConfig{})
			t.Logf("Testing %s:%s -> Success=%v", user, suggestedPwd, result.Success)
			if result.Success {
				successResult = result
				break
			}
		}
		if successResult != nil {
			break
		}
	}

	require.NotNil(t, successResult, "LLM suggestions should include valid credentials")
	assert.True(t, successResult.Success)
}

// TestHTTPWithLLM_EndToEnd_Tomcat tests Apache Tomcat credential detection
func TestHTTPWithLLM_EndToEnd_Tomcat(t *testing.T) {
	apiKey, provider := getLLMAPIKey()
	if apiKey == "" {
		t.Skip("No LLM API key available")
	}

	t.Logf("Using LLM provider: %s", provider)

	// Create Tomcat Manager-like server
	// Tomcat Manager defaults: tomcat:tomcat, admin:admin, manager:manager
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		validCreds := (username == "tomcat" && password == "tomcat") ||
			(username == "admin" && password == "admin") ||
			(username == "manager" && password == "manager")

		if !ok || !validCreds {
			w.Header().Set("Server", "Apache-Coyote/1.1")
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Apache Tomcat/9.0.80 - Error report</title></head>
<body>
<h1>HTTP Status 401 – Unauthorized</h1>
<p>This request requires HTTP authentication.</p>
<p>Apache Tomcat/9.0.80</p>
</body>
</html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`Tomcat Manager`))
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")
	ctx := context.Background()

	// Capture banner
	plugin := &Plugin{Path: "/", UseHTTPS: false}
	bannerResult := plugin.Test(ctx, target, "", "", 10*time.Second, brutus.PluginConfig{})

	require.NotNil(t, bannerResult)
	t.Logf("Captured banner:\n%s", bannerResult.Banner)

	// Get LLM suggestions
	analyzer := createAnalyzer(provider, apiKey)
	bannerInfo := brutus.BannerInfo{
		Protocol: "http",
		Target:   target,
		Banner:   bannerResult.Banner,
	}

	suggestions, err := analyzer.Analyze(ctx, bannerInfo)
	require.NoError(t, err)
	require.NotEmpty(t, suggestions)

	t.Logf("LLM suggested passwords: %v", suggestions)

	// Test suggestions
	var successResult *brutus.Result
	for _, suggestedPwd := range suggestions {
		for _, user := range []string{"tomcat", "admin", "manager"} {
			result := plugin.Test(ctx, target, user, suggestedPwd, 5*time.Second, brutus.PluginConfig{})
			t.Logf("Testing %s:%s -> Success=%v", user, suggestedPwd, result.Success)
			if result.Success {
				successResult = result
				break
			}
		}
		if successResult != nil {
			break
		}
	}

	require.NotNil(t, successResult, "LLM suggestions should include valid Tomcat credentials")
	assert.True(t, successResult.Success)
}

// TestHTTPWithLLM_BruteAPI tests the full Brute() API with LLM config
func TestHTTPWithLLM_BruteAPI(t *testing.T) {
	apiKey, provider := getLLMAPIKey()
	if apiKey == "" {
		t.Skip("No LLM API key available")
	}

	t.Logf("Using LLM provider: %s", provider)

	// Create Grafana server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "admin" {
			w.Header().Set("Server", "Grafana")
			w.Header().Set("WWW-Authenticate", `Basic realm="Grafana"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<html><head><title>Grafana</title></head><body>Grafana Login</body></html>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")

	// Use the Brute() API with LLM config
	cfg := &brutus.Config{
		Target:    target,
		Protocol:  "http",
		Usernames: []string{"admin"},
		Passwords: []string{"wrong1", "wrong2"}, // Wrong passwords - LLM should find the right one
		Timeout:   10 * time.Second,
		Threads:   1,
		LLMConfig: &brutus.LLMConfig{
			Enabled:  true,
			Provider: provider,
			APIKey:   apiKey,
		},
	}

	results, err := brutus.Brute(cfg)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// Check if we found a successful result
	var successResult *brutus.Result
	for i := range results {
		if results[i].Success {
			successResult = &results[i]
			break
		}
	}

	require.NotNil(t, successResult, "Brute() with LLM should find valid credentials")
	assert.True(t, successResult.Success)
	assert.Equal(t, "admin", successResult.Password, "Should find admin password via LLM")
	assert.True(t, successResult.LLMSuggested, "Successful credential should be marked as LLM suggested")

	t.Logf("Success! LLM suggested credentials that worked: %s:%s", successResult.Username, successResult.Password)
	t.Logf("All LLM suggestions were: %v", successResult.LLMSuggestedCreds)
}

// getLLMAPIKey returns the Anthropic API key if valid, empty string if not available or invalid
func getLLMAPIKey() (string, string) {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		// Validate the key is actually working before returning it
		if isValidAPIKey(key) {
			return key, "claude"
		}
	}
	return "", ""
}

// validatedKey caches the result of API key validation to avoid repeated calls
var (
	validatedKey   string
	keyValidated   bool
	keyValidResult bool
)

// isValidAPIKey checks if the Anthropic API key is valid by making a minimal API call
func isValidAPIKey(apiKey string) bool {
	// Use cached result if we've already validated this key
	if keyValidated && validatedKey == apiKey {
		return keyValidResult
	}

	// Create minimal request to check key validity
	reqBody := `{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(reqBody))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Cache the result
	validatedKey = apiKey
	keyValidated = true
	keyValidResult = resp.StatusCode == http.StatusOK

	return keyValidResult
}

// createAnalyzer creates a Claude LLM analyzer
func createAnalyzer(provider, apiKey string) brutus.BannerAnalyzer {
	if provider == "claude" {
		return &claude.Client{
			APIKey: apiKey,
		}
	}
	return nil
}
