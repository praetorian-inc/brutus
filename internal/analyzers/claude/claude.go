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

package claude

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	// DefaultModel is the default Claude model to use
	DefaultModel = "claude-3-haiku-20240307"
	// DefaultEndpoint is the Claude API endpoint
	DefaultEndpoint = "https://api.anthropic.com/v1/messages"
	// DefaultTimeout is the default request timeout
	DefaultTimeout = 30 * time.Second
)

func init() {
	factory := func(cfg *brutus.LLMConfig) brutus.BannerAnalyzer {
		return &Client{
			APIKey: cfg.APIKey,
			Model:  cfg.Model,
		}
	}
	// Register under both names for backward compatibility.
	// "claude" is used for text-based banner analysis.
	// "claude-vision" is used when vision capabilities are needed.
	brutus.RegisterAnalyzer("claude", factory)
	brutus.RegisterAnalyzer("claude-vision", factory)
}

// Client implements the BannerAnalyzer and VisionAnalyzer interfaces for Claude API.
// It handles both text-based banner analysis and multimodal vision requests
// (screenshot analysis, login verification, terminal OCR).
type Client struct {
	APIKey   string
	Model    string
	Endpoint string // Optional: override endpoint for testing
	Timeout  time.Duration
}

// =============================================================================
// Text-based API types (for banner analysis)
// =============================================================================

type apiRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiResponse struct {
	Content []textBlock `json:"content"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// =============================================================================
// Vision API types (for screenshot/image analysis)
// =============================================================================

type visionRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []visionMessage `json:"messages"`
}

type visionMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type   string       `json:"type"`
	Text   string       `json:"text,omitempty"`
	Source *imageSource `json:"source,omitempty"`
}

type imageSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // "image/png"
	Data      string `json:"data"`       // base64 encoded image
}

type visionResponse struct {
	Content []responseContent `json:"content"`
}

type responseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// =============================================================================
// BannerAnalyzer implementation (text-based)
// =============================================================================

// Analyze implements the BannerAnalyzer interface for text-based banner analysis.
func (c *Client) Analyze(ctx context.Context, banner brutus.BannerInfo) ([]string, error) {
	prompt := brutus.BuildPrompt(banner.Protocol, brutus.SanitizeBanner(banner.Banner))

	reqBody := apiRequest{
		Model:     c.getModel(),
		MaxTokens: 100,
		Messages: []message{{
			Role:    "user",
			Content: prompt,
		}},
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
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude api request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claude api error (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var passwords []string
	if len(apiResp.Content) > 0 {
		if err := json.Unmarshal([]byte(apiResp.Content[0].Text), &passwords); err != nil {
			return nil, fmt.Errorf("failed to parse password array: %w", err)
		}
	}

	return brutus.ValidateSuggestions(passwords), nil
}

// =============================================================================
// VisionAnalyzer implementation (screenshot-based)
// =============================================================================

// AnalyzeScreenshot analyzes a page screenshot using Claude Vision.
func (c *Client) AnalyzeScreenshot(ctx context.Context, screenshot []byte) (*PageAnalysis, error) {
	prompt := buildVisionPrompt()
	imageData := base64.StdEncoding.EncodeToString(screenshot)

	reqBody := visionRequest{
		Model:     c.getModel(),
		MaxTokens: 500,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []contentBlock{
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      imageData,
						},
					},
					{
						Type: "text",
						Text: prompt,
					},
				},
			},
		},
	}

	var analysis PageAnalysis
	if err := c.doVisionRequest(ctx, reqBody, &analysis); err != nil {
		return nil, err
	}
	return &analysis, nil
}

// VerifyLogin compares before/after screenshots to determine if login succeeded.
func (c *Client) VerifyLogin(ctx context.Context, beforeScreenshot, afterScreenshot []byte) (*LoginVerification, error) {
	prompt := buildVerificationPrompt()
	beforeData := base64.StdEncoding.EncodeToString(beforeScreenshot)
	afterData := base64.StdEncoding.EncodeToString(afterScreenshot)

	reqBody := visionRequest{
		Model:     c.getModel(),
		MaxTokens: 300,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []contentBlock{
					{
						Type: "text",
						Text: "BEFORE login attempt (Screenshot 1):",
					},
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      beforeData,
						},
					},
					{
						Type: "text",
						Text: "AFTER login attempt (Screenshot 2):",
					},
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      afterData,
						},
					},
					{
						Type: "text",
						Text: prompt,
					},
				},
			},
		},
	}

	var verification LoginVerification
	if err := c.doVisionRequest(ctx, reqBody, &verification); err != nil {
		return nil, err
	}
	return &verification, nil
}

// ReadTerminalOutput sends a screenshot of a terminal/command prompt to Claude Vision
// and returns the text content visible on the screen.
func (c *Client) ReadTerminalOutput(ctx context.Context, screenshot []byte) (string, error) {
	imageData := base64.StdEncoding.EncodeToString(screenshot)

	reqBody := visionRequest{
		Model:     c.getModel(),
		MaxTokens: 2000,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []contentBlock{
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      imageData,
						},
					},
					{
						Type: "text",
						Text: buildTerminalReadPrompt(),
					},
				},
			},
		},
	}

	text, err := c.doVisionRequestRaw(ctx, reqBody)
	if err != nil {
		return "", err
	}
	return text, nil
}

// =============================================================================
// Shared helpers
// =============================================================================

// doVisionRequest sends a vision API request and unmarshals the JSON response into result.
func (c *Client) doVisionRequest(ctx context.Context, reqBody visionRequest, result interface{}) error {
	text, err := c.doVisionRequestRaw(ctx, reqBody)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(text), result); err != nil {
		return fmt.Errorf("failed to parse response JSON: %w", err)
	}
	return nil
}

// doVisionRequestRaw sends a vision API request and returns the raw text response.
func (c *Client) doVisionRequestRaw(ctx context.Context, reqBody visionRequest) (string, error) {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.getEndpoint(), bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("claude api request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("claude api error (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp visionResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from claude")
	}

	return apiResp.Content[0].Text, nil
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

// =============================================================================
// Prompts
// =============================================================================

func buildVisionPrompt() string {
	return `Analyze this web page screenshot for a security assessment.

Determine:
1. Is this a login page? (Look for username/password fields, login buttons)
2. What application or device is this? (Router, printer, camera, NAS, enterprise app, etc.)
3. Identify the vendor and model if visible (logos, text, title)
4. Read the VISIBLE TEXT on form elements:
   - What text is on the login/submit button?
   - What labels are next to the username field?
   - What labels are next to the password field?
5. Based on the identified device, suggest ALL known default credentials

Return ONLY valid JSON:
{
  "is_login_page": true,
  "confidence": 0.95,
  "application": {
    "type": "printer",
    "vendor": "HP",
    "model": "LaserJet Pro",
    "confidence": 0.85
  },
  "form_labels": {
    "submit_button_text": "Sign In",
    "username_label": "Username",
    "password_label": "Password"
  },
  "suggested_credentials": [
    {"username": "admin", "password": ""},
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "1234"},
    {"username": "root", "password": ""},
    {"username": "root", "password": "root"}
  ]
}

Rules:
- is_login_page: true if page has authentication form
- confidence: 0.0-1.0
- application.type: router, printer, camera, nas, enterprise, unknown
- application.vendor/model: from visible branding or empty string
- form_labels: the actual visible text you can read on the page (button text, field labels)
- suggested_credentials: ALL common default credentials for this vendor/model (aim for 5-10 pairs). Include blank passwords, numeric codes like "1111" or "1234", and vendor-specific defaults.

NO commentary. ONLY the JSON object.`
}

func buildVerificationPrompt() string {
	return `Compare these two screenshots: BEFORE a login attempt and AFTER a login attempt.

Determine if the login was SUCCESSFUL or FAILED.

Signs of SUCCESS:
- Page changed to a dashboard, admin panel, or home page
- Login form is no longer visible
- Welcome message, user profile, or "Logged in as..." text appeared
- Navigation menu or settings options became available
- Logout/Sign Out button appeared

Signs of FAILURE:
- Error message visible (red text, alert box, "Invalid credentials", "Login failed")
- Login form still showing with same fields
- Page looks nearly identical to before
- Warning icons or error styling appeared

Return ONLY valid JSON in this exact format:
{
  "success": false,
  "confidence": 0.95,
  "reason": "Error message 'Invalid password' visible on the page"
}

Rules:
- success: true if login succeeded, false if it failed
- confidence: 0.0-1.0 how confident you are in this determination
- reason: brief explanation of what visual evidence led to this conclusion

NO commentary. NO explanations. ONLY the JSON object.`
}

func buildTerminalReadPrompt() string {
	return `Read the text visible on this terminal/command prompt screenshot.

Transcribe ALL visible text exactly as it appears on screen, preserving line breaks.
Include the command prompt, any commands that were typed, and all output.

Return ONLY the text content. No commentary, no JSON wrapping, no explanations.
Just the raw text visible on the terminal screen.`
}
