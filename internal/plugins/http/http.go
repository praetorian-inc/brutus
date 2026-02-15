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

// Package http implements HTTP Basic Authentication testing.
//
// This plugin is designed to work with any HTTP service that uses Basic Auth,
// including Grafana, Jenkins, Prometheus, Kibana, Tomcat, and others.
//
// The plugin captures HTTP response headers and body content to build a "banner"
// that can be analyzed by the LLM to suggest default credentials based on the
// detected service type.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	// MaxBodyRead limits how much of the response body to read for banner detection
	MaxBodyRead = 4096

	// DefaultPath is the default path to test for Basic Auth
	DefaultPath = "/"
)

func init() {
	brutus.Register("http", func() brutus.Plugin {
		return &Plugin{Path: DefaultPath, UseHTTPS: false}
	})
	brutus.Register("https", func() brutus.Plugin {
		return &Plugin{Path: DefaultPath, UseHTTPS: true}
	})
}

// Plugin implements HTTP Basic Authentication testing.
type Plugin struct {
	// Path is the URL path to test (default: "/")
	Path string

	// UseHTTPS indicates whether to use HTTPS (default: false)
	UseHTTPS bool
}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	if p.UseHTTPS {
		return "https"
	}
	return "http"
}

// Test attempts HTTP Basic Authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials (HTTP 2xx response)
// - Success=false, Error=nil: Invalid credentials (HTTP 401/403)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: p.Name(),
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build URL
	url := p.buildURL(target)

	// Create HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow self-signed certs
			},
		},
		// Don't follow redirects - we want to see the auth response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Set Basic Auth header
	// Empty username/password is used for banner capture
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	// Read limited response body for banner
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyRead))

	// Build banner from HTTP response (for LLM analysis)
	result.Banner = buildHTTPBanner(resp, bodyBytes)

	// Classify response
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Success - valid credentials
		result.Success = true

	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		// Auth failure - invalid credentials
		// Return Success=false, Error=nil

	default:
		// Unexpected status - treat as error
		result.Error = fmt.Errorf("connection error: HTTP %d", resp.StatusCode)
	}

	result.Duration = time.Since(start)
	return result
}

// buildURL constructs the full URL from target and path.
func (p *Plugin) buildURL(target string) string {
	scheme := "http"
	if p.UseHTTPS {
		scheme = "https"
	}

	path := p.Path
	if path == "" {
		path = DefaultPath
	}

	// Handle target that may or may not have port
	return fmt.Sprintf("%s://%s%s", scheme, target, path)
}

// buildHTTPBanner constructs a banner string from HTTP response for LLM analysis.
// Includes: Server header, WWW-Authenticate realm, and relevant body content.
func buildHTTPBanner(resp *http.Response, body []byte) string {
	var parts []string

	// Server header (e.g., "nginx", "Apache", "Grafana")
	if server := resp.Header.Get("Server"); server != "" {
		parts = append(parts, fmt.Sprintf("Server: %s", server))
	}

	// X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		parts = append(parts, fmt.Sprintf("X-Powered-By: %s", poweredBy))
	}

	// WWW-Authenticate header (contains realm info)
	if authHeader := resp.Header.Get("WWW-Authenticate"); authHeader != "" {
		parts = append(parts, fmt.Sprintf("WWW-Authenticate: %s", authHeader))
	}

	// Extract application identifiers from body
	bodyStr := string(body)
	if appInfo := extractAppIdentifiers(bodyStr); appInfo != "" {
		parts = append(parts, fmt.Sprintf("App-Identifier: %s", appInfo))
	}

	// Include truncated body if it might be useful
	if bodyStr != "" && len(bodyStr) <= 500 {
		// Clean up whitespace
		bodyStr = strings.Join(strings.Fields(bodyStr), " ")
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		parts = append(parts, fmt.Sprintf("Body: %s", bodyStr))
	}

	return strings.Join(parts, "\n")
}

// extractAppIdentifiers looks for common application names in HTML/JSON response.
// Only includes applications that commonly use HTTP Basic Auth.
func extractAppIdentifiers(body string) string {
	// Lowercase for matching
	lower := strings.ToLower(body)

	// Applications that commonly use HTTP Basic Auth
	// (excludes form-based auth apps like Splunk, GitLab, Portainer, etc.)
	apps := []struct {
		name    string
		markers []string
	}{
		// Monitoring/metrics - commonly use Basic Auth
		{"Grafana", []string{"grafana", "grafana-app"}},
		{"Prometheus", []string{"prometheus"}},
		{"Nagios", []string{"nagios"}},

		// CI/CD and DevOps - support Basic Auth
		{"Jenkins", []string{"jenkins", "hudson"}},
		{"Nexus", []string{"nexus repository", "sonatype nexus"}},
		{"Artifactory", []string{"artifactory", "jfrog"}},
		{"SonarQube", []string{"sonarqube", "sonar"}},

		// Web servers/app servers - use Basic Auth for admin
		{"Apache Tomcat", []string{"apache tomcat", "tomcat manager"}},
		{"Traefik", []string{"traefik"}},

		// Message brokers - management UIs use Basic Auth
		{"RabbitMQ", []string{"rabbitmq"}},
		{"ActiveMQ", []string{"activemq"}},

		// Databases with HTTP APIs - use Basic Auth
		{"Elasticsearch", []string{"elasticsearch", "elastic"}},
		{"CouchDB", []string{"couchdb"}},
		{"InfluxDB", []string{"influxdb"}},

		// Container registries - use Basic Auth
		{"Docker Registry", []string{"docker registry", "docker-registry"}},

		// Service mesh/discovery - can use Basic Auth
		{"Consul", []string{"consul"}},
		{"Etcd", []string{"etcd"}},

		// Legacy admin panels
		{"phpMyAdmin", []string{"phpmyadmin"}},
		{"Webmin", []string{"webmin"}},
	}

	var found []string
	for _, app := range apps {
		for _, marker := range app.markers {
			if strings.Contains(lower, marker) {
				found = append(found, app.name)
				break
			}
		}
	}

	return strings.Join(found, ", ")
}
