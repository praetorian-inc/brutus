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

package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.RegisterUnauthChecker("docker", func() brutus.UnauthOnlyChecker {
		return &Checker{}
	})
}

// Checker detects unauthenticated Docker daemon API access.
type Checker struct{}

// Name returns the protocol name.
func (c *Checker) Name() string {
	return "docker"
}

// CheckUnauth probes for an exposed Docker daemon API without authentication.
func (c *Checker) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("docker", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "2375")

	// Use HTTPS for port 2376 or when TLS is configured
	scheme := "http"
	if port == "2376" || pluginCfg.TLSMode == "verify" || pluginCfg.TLSMode == "skip-verify" {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%s/version", scheme, host, port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return result
	}

	client, err := brutus.NewHTTPClientWithProxy(timeout, brutus.BuildTLSConfig(pluginCfg.TLSMode), pluginCfg.ProxyURL)
	if err != nil {
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bannerText := "[CRITICAL] Docker daemon API exposed without authentication"
	if len(bodyBytes) > 0 {
		bannerText += fmt.Sprintf("\nVersion info: %s", string(bodyBytes))
	}

	result.Success = true
	result.Banner = bannerText
	return result
}
