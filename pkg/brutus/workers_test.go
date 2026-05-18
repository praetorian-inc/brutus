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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCaptureBanner_EmptyUsernames(t *testing.T) {
	// Setup: Config with only Credentials (no Usernames), HTTP protocol, LLM enabled
	cfg := &Config{
		Target:   "example.com:80",
		Protocol: "http",
		Credentials: []Credential{
			{Username: "admin", Password: "password123"},
		},
		Usernames: []string{}, // EMPTY - triggers the bug
		Timeout:   10 * time.Second,
		LLMConfig: &LLMConfig{
			Enabled:  true,
			Provider: "claude",
		},
	}

	// Create mock plugin
	mockPlugin := &mockHTTPPlugin{}

	// This should NOT panic
	ctx := context.Background()
	banner := captureBanner(ctx, cfg, mockPlugin)

	// Should return a valid BannerInfo with empty Banner (not crash)
	assert.Equal(t, "http", banner.Protocol)
	assert.Equal(t, "example.com:80", banner.Target)
	// Banner may be empty, which is fine
}

type mockHTTPPlugin struct{}

func (m *mockHTTPPlugin) Name() string { return "http" }

func (m *mockHTTPPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	return &Result{
		Protocol: "http",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Banner:   "HTTP/1.1 401 Unauthorized",
	}
}
