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

package kubernetes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.RegisterUnauthChecker("kubernetes", func() brutus.UnauthOnlyChecker {
		return &Checker{}
	})
}

// Checker detects unauthenticated Kubernetes API access.
type Checker struct{}

// Name returns the protocol name.
func (c *Checker) Name() string {
	return "kubernetes"
}

// CheckUnauth probes for Kubernetes anonymous access.
// For the API server, it confirms anonymous access by requesting a protected
// resource (/api/v1/namespaces) since /version is publicly accessible by
// default RBAC policy. For kubelet (port 10250), it checks the /pods endpoint.
func (c *Checker) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("kubernetes", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "6443")

	// Default to skip-verify for K8s (self-signed certs are common)
	tlsMode := pluginCfg.TLSMode
	if tlsMode == "" {
		tlsMode = "skip-verify"
	}
	client, err := brutus.NewHTTPClientWithProxy(timeout, brutus.BuildTLSConfig(tlsMode), pluginCfg.ProxyURL)
	if err != nil {
		return result
	}
	scheme := brutus.SchemeFromTLSMode(tlsMode)

	// For kubelet (port 10250), check the /pods endpoint directly
	if port == "10250" {
		return c.checkKubelet(ctx, client, scheme, host, port, result)
	}

	// For API server: /version is publicly accessible by default RBAC,
	// so we must probe a protected resource to confirm anonymous access.
	protectedURL := fmt.Sprintf("%s://%s:%s/api/v1/namespaces", scheme, host, port)
	req, err := http.NewRequestWithContext(ctx, "GET", protectedURL, http.NoBody)
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

	// Anonymous access to protected resources confirmed — get version info
	bannerText := "[CRITICAL] Kubernetes anonymous access enabled"
	versionURL := fmt.Sprintf("%s://%s:%s/version", scheme, host, port)
	vReq, err := http.NewRequestWithContext(ctx, "GET", versionURL, http.NoBody)
	if err == nil {
		vResp, err := client.Do(vReq)
		if err == nil {
			vBody, _ := io.ReadAll(io.LimitReader(vResp.Body, 1024))
			_ = vResp.Body.Close()
			if len(vBody) > 0 {
				bannerText += fmt.Sprintf("\nVersion info: %s", string(vBody))
			}
		}
	}

	result.Success = true
	result.Banner = bannerText
	return result
}

// checkKubelet probes the kubelet /pods endpoint for unauthenticated access.
func (c *Checker) checkKubelet(ctx context.Context, client *http.Client, scheme, host, port string, result *brutus.Result) *brutus.Result {
	podsURL := fmt.Sprintf("%s://%s:%s/pods", scheme, host, port)
	req, err := http.NewRequestWithContext(ctx, "GET", podsURL, http.NoBody)
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

	result.Success = true
	result.Banner = "[CRITICAL] Kubelet API accessible without authentication (/pods endpoint)"
	return result
}
