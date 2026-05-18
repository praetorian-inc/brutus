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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	brutusinput "github.com/praetorian-inc/brutus/pkg/brutus/input"
)

// TestNervaIntegration tests the full pipeline: nerva -> brutus
// This test requires nerva to be installed.
func TestNervaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if nerva is installed
	if _, err := exec.LookPath("nerva"); err != nil {
		t.Skip("Skipping: nerva not installed (run: go install github.com/praetorian-inc/nerva/cmd/nerva@latest)")
	}

	// Start a test HTTP server with Basic Auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Test Server"`)
			w.Header().Set("Server", "TestServer/1.0")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome"))
	}))
	defer server.Close()

	// Extract host:port from server URL
	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Run nerva against the test server
	nrvCmd := exec.Command("nerva", "-t", serverAddr, "--json")
	nrvOutput, err := nrvCmd.Output()
	if err != nil {
		t.Fatalf("nerva failed: %v", err)
	}

	t.Logf("nerva output: %s", string(nrvOutput))

	// Verify nerva detected the HTTP service
	var nrvResult brutusinput.NervaResult
	if err := json.Unmarshal(bytes.TrimSpace(nrvOutput), &nrvResult); err != nil {
		t.Fatalf("Failed to parse nerva JSON: %v (output: %s)", err, string(nrvOutput))
	}

	assert.Equal(t, "http", nrvResult.Protocol, "nerva should detect HTTP protocol")

	// Build brutus binary
	buildCmd := exec.Command("go", "build", "-o", "brutus_test", ".")
	buildCmd.Dir = "."
	buildCmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build brutus: %v\n%s", err, string(output))
	}
	defer os.Remove("brutus_test")

	// Run brutus with nerva output via stdin (auto-detected)
	brutusCmd := exec.Command("./brutus_test", "web", "-c", "admin:admin", "--json")
	brutusCmd.Stdin = bytes.NewReader(nrvOutput)
	brutusOutput, err := brutusCmd.CombinedOutput()

	t.Logf("brutus output: %s", string(brutusOutput))

	// Parse brutus JSONL output (one JSON object per line)
	lines := strings.Split(strings.TrimSpace(string(brutusOutput)), "\n")
	require.NotEmpty(t, lines, "brutus should have produced results")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &result); err != nil {
		t.Fatalf("Failed to parse JSON line: %v (output: %s)", err, string(brutusOutput))
	}

	assert.Equal(t, "http", result["protocol"], "protocol should be http")
	assert.Contains(t, result["target"], serverAddr, "target should match")
}

// TestNervaJSONParsing tests parsing of nerva JSON format
func TestNervaJSONParsing(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		wantProtocol string
		wantIP       string
		wantPort     int
	}{
		{
			name:         "HTTP protocol",
			json:         `{"ip":"192.168.1.1","port":80,"protocol":"http","tls":false,"transport":"tcp"}`,
			wantProtocol: "http",
			wantIP:       "192.168.1.1",
			wantPort:     80,
		},
		{
			name:         "SSH protocol",
			json:         `{"ip":"10.0.0.1","port":22,"protocol":"ssh","tls":false,"transport":"tcp","version":"OpenSSH_8.9","metadata":{"banner":"SSH-2.0-OpenSSH_8.9"}}`,
			wantProtocol: "ssh",
			wantIP:       "10.0.0.1",
			wantPort:     22,
		},
		{
			name:         "MySQL protocol",
			json:         `{"ip":"db.example.com","port":3306,"protocol":"mysql","tls":false,"transport":"tcp"}`,
			wantProtocol: "mysql",
			wantIP:       "db.example.com",
			wantPort:     3306,
		},
		{
			name:         "HTTPS protocol",
			json:         `{"ip":"secure.example.com","port":443,"protocol":"https","tls":true,"transport":"tcp"}`,
			wantProtocol: "https",
			wantIP:       "secure.example.com",
			wantPort:     443,
		},
		{
			name:         "SNMP protocol",
			json:         `{"ip":"192.168.1.1","port":161,"protocol":"snmp","tls":false,"transport":"udp"}`,
			wantProtocol: "snmp",
			wantIP:       "192.168.1.1",
			wantPort:     161,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nrv brutusinput.NervaResult
			err := json.Unmarshal([]byte(tt.json), &nrv)
			require.NoError(t, err)

			assert.Equal(t, tt.wantProtocol, nrv.Protocol)
			assert.Equal(t, tt.wantIP, nrv.IP)
			assert.Equal(t, tt.wantPort, nrv.Port)

			// Verify protocol mapping works
			protocol := brutusinput.MapServiceToProtocol(nrv.Protocol)
			assert.NotEmpty(t, protocol, "protocol should map to a brutus protocol")
		})
	}
}

// TestServiceToProtocolMapping tests the nerva service to brutus protocol mapping
func TestServiceToProtocolMapping(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		// Network services
		{"ssh", "ssh"},
		{"SSH", "ssh"}, // case insensitive
		{"ftp", "ftp"},
		{"telnet", "telnet"},
		{"vnc", "vnc"},

		// Enterprise
		{"smb", "smb"},
		{"ldap", "ldap"},

		// Databases
		{"mysql", "mysql"},
		{"postgresql", "postgresql"},
		{"postgres", "postgresql"},
		{"mssql", "mssql"},
		{"mongodb", "mongodb"},
		{"redis", "redis"},
		{"cassandra", "cassandra"},
		{"elasticsearch", "elasticsearch"},

		// HTTP
		{"http", "http"},
		{"https", "https"},

		// SNMP
		{"snmp", "snmp"},

		// Unsupported
		{"unknown", ""},
		{"dns", ""},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			got := brutusinput.MapServiceToProtocol(tt.service)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestStdinMode tests stdin auto-detection with simulated nerva output
func TestStdinMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start a test server that accepts specific credentials
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testpass" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Success"))
	}))
	defer server.Close()

	// Extract host and port
	parts := strings.Split(strings.TrimPrefix(server.URL, "http://"), ":")
	host := parts[0]
	port := parts[1]

	// Create nerva-style JSON input
	nrvJSON := fmt.Sprintf(`{"ip":"%s","port":%s,"protocol":"http","tls":false,"transport":"tcp"}`, host, port)

	// Build brutus
	buildCmd := exec.Command("go", "build", "-o", "brutus_test", ".")
	buildCmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build brutus: %v\n%s", err, string(output))
	}
	defer os.Remove("brutus_test")

	// Run brutus with stdin and valid credentials (auto-detected)
	brutusCmd := exec.Command("./brutus_test", "web", "-c", "testuser:testpass", "--json")
	brutusCmd.Stdin = strings.NewReader(nrvJSON)
	output, err := brutusCmd.CombinedOutput()

	t.Logf("Output: %s", string(output))

	// Should succeed (exit 0 for valid credentials)
	require.NoError(t, err, "brutus should exit 0 on successful auth")

	// Parse JSONL output (one JSON object per line)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	require.NotEmpty(t, lines, "should have at least one result line")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &result); err != nil {
		t.Fatalf("Failed to parse JSON line: %v", err)
	}

	assert.Equal(t, "http", result["protocol"])
	assert.Equal(t, "testuser", result["username"])
	assert.Equal(t, "testpass", result["password"])
}
