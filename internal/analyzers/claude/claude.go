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
	// Register the Claude analyzer factory
	brutus.RegisterAnalyzer("claude", func(cfg *brutus.LLMConfig) brutus.BannerAnalyzer {
		return &Client{
			APIKey: cfg.APIKey,
			Model:  cfg.Model,
		}
	})
}

// Client implements the BannerAnalyzer and VisionAnalyzer interfaces for Claude API
type Client struct {
	APIKey   string
	Model    string
	Endpoint string        // Optional: override endpoint for testing
	Timeout  time.Duration
}

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

// Analyze implements the BannerAnalyzer interface
func (c *Client) Analyze(ctx context.Context, banner brutus.BannerInfo) ([]string, error) {
	// 1. Build prompt with sanitized banner
	prompt := brutus.BuildPrompt(banner.Protocol, brutus.SanitizeBanner(banner.Banner))

	// 2. Create API request
	reqBody := apiRequest{
		Model:     c.getModel(),
		MaxTokens: 100, // Short response - just a JSON array
		Messages: []message{{
			Role:    "user",
			Content: prompt,
		}},
	}

	// 3. Marshal request body
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 4. Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.getEndpoint(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 5. Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// 6. Send request
	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude api request failed: %w", err)
	}
	defer resp.Body.Close()

	// 7. Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claude api error (status %d): %s", resp.StatusCode, string(body))
	}

	// 8. Parse response
	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// 9. Extract JSON array from response
	var passwords []string
	if len(apiResp.Content) > 0 {
		if err := json.Unmarshal([]byte(apiResp.Content[0].Text), &passwords); err != nil {
			return nil, fmt.Errorf("failed to parse password array: %w", err)
		}
	}

	// 10. Validate and return
	return brutus.ValidateSuggestions(passwords), nil
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
