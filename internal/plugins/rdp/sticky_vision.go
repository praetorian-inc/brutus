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

package rdp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultVisionModel    = "claude-sonnet-4-5-20250929"
	maxVisionResponseSize = 64 * 1024 // 64KB limit for API response body
)

// analyzeStickyKeysVision sends the post-keystroke screenshot to Claude Vision API
// and asks if it shows a command prompt window.
// Returns (verdict, description).
func analyzeStickyKeysVision(ctx context.Context, pngData []byte, apiKey string) (verdict, description string) {
	if apiKey == "" {
		return "", "no API key"
	}

	b64Image := base64.StdEncoding.EncodeToString(pngData)

	model := os.Getenv("BRUTUS_VISION_MODEL")
	if model == "" {
		model = defaultVisionModel
	}

	requestBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 256,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "image",
						"source": map[string]string{
							"type":       "base64",
							"media_type": "image/png",
							"data":       b64Image,
						},
					},
					{
						"type": "text",
						"text": "This is a screenshot of a Windows RDP login screen after pressing Shift 5 times. " +
							"Does this screenshot show a command prompt (cmd.exe) or PowerShell window? " +
							"Respond with ONLY one of: BACKDOOR_CONFIRMED, STICKY_KEYS_DIALOG, NO_CHANGE, UNCLEAR. " +
							"BACKDOOR_CONFIRMED means a command prompt or terminal window is visible. " +
							"STICKY_KEYS_DIALOG means the normal Windows Sticky Keys accessibility dialog appeared. " +
							"NO_CHANGE means the screen looks the same as before. " +
							"UNCLEAR means you cannot determine what is shown.",
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Sprintf("marshal error: %v", err)
	}

	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Sprintf("request error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Sprintf("api error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxVisionResponseSize))
	if err != nil {
		return "", fmt.Sprintf("read error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Sprintf("api status %d", resp.StatusCode)
	}

	// Parse response
	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Sprintf("parse error: %v", err)
	}

	if len(apiResp.Content) == 0 {
		return "", "empty response"
	}

	answer := strings.TrimSpace(strings.ToUpper(apiResp.Content[0].Text))

	switch {
	case strings.Contains(answer, "BACKDOOR_CONFIRMED"):
		return "backdoor_confirmed", "Vision API: command prompt detected"
	case strings.Contains(answer, "STICKY_KEYS_DIALOG"):
		return "vulnerable", "Vision API: normal sticky keys dialog"
	case strings.Contains(answer, "NO_CHANGE"):
		return "clean", "Vision API: no change detected"
	default:
		return "", fmt.Sprintf("Vision API: %s", answer)
	}
}
