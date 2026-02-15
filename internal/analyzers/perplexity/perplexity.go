// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package perplexity implements credential research using Perplexity API
package perplexity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	DefaultEndpoint = "https://api.perplexity.ai/chat/completions"
	DefaultModel    = "sonar" // Current Perplexity model (replaces deprecated llama-3.1-sonar-small-128k-online)
	DefaultTimeout  = 30 * time.Second
)

func init() {
	brutus.RegisterAnalyzer("perplexity", func(cfg *brutus.LLMConfig) brutus.BannerAnalyzer {
		return &Client{
			APIKey: cfg.APIKey,
			Model:  cfg.Model,
		}
	})
}

// Client implements CredentialResearcher using Perplexity API
type Client struct {
	APIKey   string
	Model    string
	Endpoint string        // Optional: override endpoint
	Timeout  time.Duration // Optional: request timeout
}

type apiRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiResponse struct {
	Choices []choice `json:"choices"`
}

type choice struct {
	Message message `json:"message"`
}

// Analyze implements brutus.BannerAnalyzer interface
// Extracts application info from banner JSON and researches credentials
func (c *Client) Analyze(ctx context.Context, banner brutus.BannerInfo) ([]string, error) {
	creds, err := c.AnalyzeCredentials(ctx, banner)
	if err != nil {
		return nil, err
	}

	// Extract unique passwords
	passwords := make([]string, 0, len(creds))
	seen := make(map[string]bool)
	for _, cred := range creds {
		if !seen[cred.Password] {
			passwords = append(passwords, cred.Password)
			seen[cred.Password] = true
		}
	}

	return passwords, nil
}

// AnalyzeCredentials implements brutus.CredentialAnalyzer interface
// Returns full credential pairs (username + password) for the identified application
func (c *Client) AnalyzeCredentials(ctx context.Context, banner brutus.BannerInfo) ([]brutus.Credential, error) {
	// Parse application info from banner (JSON format from vision analyzer)
	var bannerData struct {
		Application struct {
			Type   string `json:"type"`
			Vendor string `json:"vendor"`
			Model  string `json:"model"`
		} `json:"application"`
	}

	var creds []Credential
	var err error

	if jsonErr := json.Unmarshal([]byte(banner.Banner), &bannerData); jsonErr != nil {
		// Fallback: use banner as plain text
		creds, err = c.researchFromTextWithPairs(ctx, banner.Banner)
	} else {
		// Research credentials for identified application
		creds, err = c.ResearchCredentials(ctx,
			bannerData.Application.Type,
			bannerData.Application.Vendor,
			bannerData.Application.Model,
		)
	}

	if err != nil {
		return nil, err
	}

	// Convert to brutus.Credential
	result := make([]brutus.Credential, 0, len(creds))
	for _, cred := range creds {
		result = append(result, brutus.Credential{
			Username: cred.Username,
			Password: cred.Password,
		})
	}

	return result, nil
}

// ResearchCredentials queries Perplexity for default credentials
func (c *Client) ResearchCredentials(ctx context.Context, appType, vendor, model string) ([]Credential, error) {
	// Build search query
	query := buildSearchQuery(appType, vendor, model)

	// Create API request
	reqBody := apiRequest{
		Model: c.getModel(),
		Messages: []message{
			{
				Role:    "user",
				Content: query,
			},
		},
	}

	// Marshal request
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	endpoint := c.getEndpoint()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	// Send request
	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perplexity api request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("perplexity api error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return []Credential{}, nil
	}

	// Extract credentials from response text
	creds := parseCredentials(apiResp.Choices[0].Message.Content)

	// Mark source
	for i := range creds {
		creds[i].Source = "perplexity"
	}

	return creds, nil
}

// researchFromTextWithPairs handles plain text banner and returns credential pairs
func (c *Client) researchFromTextWithPairs(ctx context.Context, text string) ([]Credential, error) {
	reqBody := apiRequest{
		Model: c.getModel(),
		Messages: []message{
			{
				Role:    "user",
				Content: fmt.Sprintf("What are the default credentials for this device/application? %s", text),
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.getEndpoint(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api error: status %d", resp.StatusCode)
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return []Credential{}, nil
	}

	return parseCredentials(apiResp.Choices[0].Message.Content), nil
}

// researchFromText handles plain text banner (legacy - returns passwords only)
//
//nolint:unused // Kept for potential future use with password-only analysis
func (c *Client) researchFromText(ctx context.Context, text string) ([]string, error) {
	reqBody := apiRequest{
		Model: c.getModel(),
		Messages: []message{
			{
				Role:    "user",
				Content: fmt.Sprintf("What are the default credentials for this device/application? %s", text),
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.getEndpoint(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api error: status %d", resp.StatusCode)
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return []string{}, nil
	}

	creds := parseCredentials(apiResp.Choices[0].Message.Content)
	passwords := make([]string, 0, len(creds))
	for _, cred := range creds {
		passwords = append(passwords, cred.Password)
	}

	return passwords, nil
}

func (c *Client) getModel() string {
	if c.Model != "" {
		return c.Model
	}
	return DefaultModel
}

func (c *Client) getEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return DefaultEndpoint
}

func (c *Client) getTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// buildSearchQuery creates the search query for credential research
func buildSearchQuery(appType, vendor, model string) string {
	parts := []string{}

	if vendor != "" {
		parts = append(parts, vendor)
	}
	if model != "" {
		parts = append(parts, model)
	}
	if appType != "" && appType != "unknown" {
		parts = append(parts, appType)
	}

	device := strings.Join(parts, " ")
	if device == "" {
		device = "unknown device"
	}

	return fmt.Sprintf(`What are the default username and password credentials for %s?

Search for factory default login credentials. Include:
1. The most common default username and password
2. Any alternate default credentials
3. Service account credentials if applicable

Format each credential clearly as username:password or username/password.`, device)
}

// parseCredentials extracts credential pairs from text response
func parseCredentials(text string) []Credential {
	creds := []Credential{}
	seen := make(map[string]bool)

	// Pattern 1: username:password or username/password
	colonPattern := regexp.MustCompile(`(?i)(?:^|\s|-)([a-zA-Z0-9_]+)[:/]([a-zA-Z0-9_!@#$%^&*()]+)(?:\s|$|,|\.|\))`)
	matches := colonPattern.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			key := m[1] + ":" + m[2]
			if !seen[key] {
				creds = append(creds, Credential{Username: m[1], Password: m[2]})
				seen[key] = true
			}
		}
	}

	// Pattern 2: Username: X, Password: Y (multiline or same line)
	userPattern := regexp.MustCompile(`(?i)username[:\s]+([a-zA-Z0-9_]+)`)
	passPattern := regexp.MustCompile(`(?i)password[:\s]+([a-zA-Z0-9_!@#$%^&*()\s]*)`)

	userMatches := userPattern.FindAllStringSubmatch(text, -1)
	passMatches := passPattern.FindAllStringSubmatch(text, -1)

	// Pair them up
	for i := 0; i < len(userMatches) && i < len(passMatches); i++ {
		username := strings.TrimSpace(userMatches[i][1])
		password := strings.TrimSpace(passMatches[i][1])
		// Clean up password (may have trailing text)
		password = strings.Split(password, " ")[0]
		password = strings.Split(password, ",")[0]

		if username != "" {
			key := username + ":" + password
			if !seen[key] {
				creds = append(creds, Credential{Username: username, Password: password})
				seen[key] = true
			}
		}
	}

	// Sanitize, deduplicate and validate
	validCreds := []Credential{}
	finalSeen := make(map[string]bool)
	for _, c := range creds {
		sanitizeCredential(&c)
		key := c.Username + ":" + c.Password
		if !finalSeen[key] && isValidCredential(c) {
			validCreds = append(validCreds, c)
			finalSeen[key] = true
		}
	}

	// Limit to reasonable number
	if len(validCreds) > 10 {
		validCreds = validCreds[:10]
	}

	return validCreds
}

// sanitizeCredential removes markdown artifacts and normalizes credentials
func sanitizeCredential(c *Credential) {
	// Strip markdown emphasis markers (**, *, `, etc.)
	markdownChars := []string{"**", "*", "`", "~", "_"}
	for _, m := range markdownChars {
		c.Username = strings.ReplaceAll(c.Username, m, "")
		c.Password = strings.ReplaceAll(c.Password, m, "")
	}
	// Trim whitespace
	c.Username = strings.TrimSpace(c.Username)
	c.Password = strings.TrimSpace(c.Password)
}

// isValidCredential checks if a credential looks valid
func isValidCredential(c Credential) bool {
	// Username must be non-empty
	if c.Username == "" {
		return false
	}

	// Username should be reasonably short (not a sentence or URL)
	if len(c.Username) > 30 {
		return false
	}

	// Filter out common false positives from markdown/prose parsing
	lowerUser := strings.ToLower(c.Username)
	invalidUsers := []string{
		"http", "https", "ftp", "ssh", "the", "default", "example",
		"devices", "notes", "consideration", "important", "warning",
		"note", "see", "for", "more", "information", "details",
		"typically", "usually", "common", "standard", "model",
	}
	for _, invalid := range invalidUsers {
		if lowerUser == invalid {
			return false
		}
	}

	// Password should not be just special characters (like "**" from markdown)
	if c.Password != "" {
		hasAlphanumeric := false
		for _, r := range c.Password {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				hasAlphanumeric = true
				break
			}
		}
		if !hasAlphanumeric {
			return false
		}
	}

	// Password can be empty (some devices have no password by default)
	// But filter obvious non-passwords
	lowerPass := strings.ToLower(c.Password)
	invalidPass := []string{"none", "blank", "empty", "n/a", "na"}
	for _, invalid := range invalidPass {
		if lowerPass == invalid {
			c.Password = "" // Convert to actual empty
			return true
		}
	}

	return true
}
