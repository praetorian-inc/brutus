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
	"crypto/tls"
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
// Checks the API server /version endpoint and, for kubelet (port 10250),
// the /pods endpoint. Always uses TLS with InsecureSkipVerify since K8s
// API servers typically use self-signed certificates.
func (c *Checker) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("kubernetes", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "6443")

	// K8s API server uses TLS with typically self-signed certs
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // K8s API servers use self-signed certs
			},
		},
	}

	// Probe /version endpoint (works for both API server and kubelet)
	scheme := "https"
	url := fmt.Sprintf("%s://%s:%s/version", scheme, host, port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
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
	bannerText := "[CRITICAL] Kubernetes anonymous access enabled"
	if len(bodyBytes) > 0 {
		bannerText += fmt.Sprintf("\nVersion info: %s", string(bodyBytes))
	}

	// For kubelet (port 10250), also check /pods
	if port == "10250" {
		podsURL := fmt.Sprintf("%s://%s:%s/pods", scheme, host, port)
		podsReq, err := http.NewRequestWithContext(ctx, "GET", podsURL, http.NoBody)
		if err == nil {
			podsResp, err := client.Do(podsReq)
			if err == nil {
				defer func() { _ = podsResp.Body.Close() }()
				if podsResp.StatusCode == http.StatusOK {
					bannerText += "\nKubelet /pods endpoint also accessible"
				}
			}
		}
	}

	result.Success = true
	result.Banner = bannerText
	return result
}
