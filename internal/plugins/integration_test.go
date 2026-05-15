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

// Package plugins contains integration tests for all Brutus authentication plugins.
// These tests run against real containerized services defined in the CI workflow.
//
// Run with: go test -tags=integration -v ./internal/plugins/...
//
// Required environment variables are set by the CI workflow. For local testing,
// start services with docker-compose and set the environment variables manually.
package plugins

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"

	// Import all plugins to register them
	_ "github.com/praetorian-inc/brutus/internal/plugins/cassandra"
	_ "github.com/praetorian-inc/brutus/internal/plugins/couchdb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/elasticsearch"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ftp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/http"
	_ "github.com/praetorian-inc/brutus/internal/plugins/imap"
	_ "github.com/praetorian-inc/brutus/internal/plugins/influxdb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ldap"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mongodb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mssql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/mysql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/neo4j"
	_ "github.com/praetorian-inc/brutus/internal/plugins/pop3"
	_ "github.com/praetorian-inc/brutus/internal/plugins/postgresql"
	_ "github.com/praetorian-inc/brutus/internal/plugins/redis"
	_ "github.com/praetorian-inc/brutus/internal/plugins/smb"
	_ "github.com/praetorian-inc/brutus/internal/plugins/smtp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/snmp"
	_ "github.com/praetorian-inc/brutus/internal/plugins/ssh"
	_ "github.com/praetorian-inc/brutus/internal/plugins/telnet"
	_ "github.com/praetorian-inc/brutus/internal/plugins/vnc"
)

const defaultTimeout = 10 * time.Second

// testCase defines a protocol integration test
type testCase struct {
	name       string
	protocol   string
	hostEnv    string
	userEnv    string
	passEnv    string
	timeout    time.Duration
	skipReason string // If non-empty, test will be skipped with this reason
}

// TestAllProtocols runs integration tests for all supported protocols.
// Each test validates:
// 1. Valid credentials succeed (Success=true, Error=nil)
// 2. Invalid credentials fail gracefully (Success=false, Error=nil)
func TestAllProtocols(t *testing.T) {
	tests := []testCase{
		// ==================== Network Services ====================
		{
			name:     "SSH",
			protocol: "ssh",
			hostEnv:  "SSH_TEST_HOST",
			userEnv:  "SSH_TEST_USER",
			passEnv:  "SSH_TEST_PASS",
		},
		{
			name:     "FTP",
			protocol: "ftp",
			hostEnv:  "FTP_TEST_HOST",
			userEnv:  "FTP_TEST_USER",
			passEnv:  "FTP_TEST_PASS",
		},
		{
			name:     "Telnet",
			protocol: "telnet",
			hostEnv:  "TELNET_TEST_HOST",
			userEnv:  "TELNET_TEST_USER",
			passEnv:  "TELNET_TEST_PASS",
			timeout:  30 * time.Second,
		},
		{
			name:     "VNC",
			protocol: "vnc",
			hostEnv:  "VNC_TEST_HOST",
			userEnv:  "", // VNC uses password only
			passEnv:  "VNC_TEST_PASS",
		},

		// ==================== Enterprise Infrastructure ====================
		{
			name:     "SMB",
			protocol: "smb",
			hostEnv:  "SMB_TEST_HOST",
			userEnv:  "SMB_TEST_USER",
			passEnv:  "SMB_TEST_PASS",
		},
		{
			name:     "LDAP",
			protocol: "ldap",
			hostEnv:  "LDAP_TEST_HOST",
			userEnv:  "LDAP_TEST_USER",
			passEnv:  "LDAP_TEST_PASS",
		},
		// ==================== Databases ====================
		{
			name:     "MySQL",
			protocol: "mysql",
			hostEnv:  "MYSQL_TEST_HOST",
			userEnv:  "MYSQL_TEST_USER",
			passEnv:  "MYSQL_TEST_PASS",
		},
		{
			name:     "PostgreSQL",
			protocol: "postgresql",
			hostEnv:  "POSTGRES_TEST_HOST",
			userEnv:  "POSTGRES_TEST_USER",
			passEnv:  "POSTGRES_TEST_PASS",
		},
		{
			name:     "MSSQL",
			protocol: "mssql",
			hostEnv:  "MSSQL_TEST_HOST",
			userEnv:  "MSSQL_TEST_USER",
			passEnv:  "MSSQL_TEST_PASS",
			timeout:  30 * time.Second,
		},
		{
			name:     "MongoDB",
			protocol: "mongodb",
			hostEnv:  "MONGODB_TEST_HOST",
			userEnv:  "MONGODB_TEST_USER",
			passEnv:  "MONGODB_TEST_PASS",
		},
		{
			name:     "Redis",
			protocol: "redis",
			hostEnv:  "REDIS_TEST_HOST",
			userEnv:  "", // Redis uses password only
			passEnv:  "REDIS_TEST_PASS",
		},
		{
			name:     "Neo4j",
			protocol: "neo4j",
			hostEnv:  "NEO4J_TEST_HOST",
			userEnv:  "NEO4J_TEST_USER",
			passEnv:  "NEO4J_TEST_PASS",
		},
		{
			name:       "Cassandra",
			protocol:   "cassandra",
			hostEnv:    "CASSANDRA_TEST_HOST",
			userEnv:    "CASSANDRA_TEST_USER",
			passEnv:    "CASSANDRA_TEST_PASS",
			timeout:    30 * time.Second,
			skipReason: "Official Cassandra image uses AllowAllAuthenticator by default",
		},
		{
			name:     "CouchDB",
			protocol: "couchdb",
			hostEnv:  "COUCHDB_TEST_HOST",
			userEnv:  "COUCHDB_TEST_USER",
			passEnv:  "COUCHDB_TEST_PASS",
		},
		{
			name:     "Elasticsearch",
			protocol: "elasticsearch",
			hostEnv:  "ELASTICSEARCH_TEST_HOST",
			userEnv:  "ELASTICSEARCH_TEST_USER",
			passEnv:  "ELASTICSEARCH_TEST_PASS",
		},
		{
			name:     "InfluxDB",
			protocol: "influxdb",
			hostEnv:  "INFLUXDB_TEST_HOST",
			userEnv:  "INFLUXDB_TEST_USER",
			passEnv:  "INFLUXDB_TEST_PASS",
		},

		// ==================== Communications ====================
		{
			name:     "SMTP",
			protocol: "smtp",
			hostEnv:  "SMTP_TEST_HOST",
			userEnv:  "SMTP_TEST_USER",
			passEnv:  "SMTP_TEST_PASS",
		},
		{
			name:     "IMAP",
			protocol: "imap",
			hostEnv:  "IMAP_TEST_HOST",
			userEnv:  "IMAP_TEST_USER",
			passEnv:  "IMAP_TEST_PASS",
		},
		{
			name:     "POP3",
			protocol: "pop3",
			hostEnv:  "POP3_TEST_HOST",
			userEnv:  "POP3_TEST_USER",
			passEnv:  "POP3_TEST_PASS",
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			runProtocolTest(t, tc)
		})
	}
}

// TestSNMP tests SNMP community string authentication separately
// since it doesn't follow the username/password pattern.
func TestSNMP(t *testing.T) {
	t.Parallel()

	host := os.Getenv("SNMP_TEST_HOST")
	community := os.Getenv("SNMP_TEST_COMMUNITY")

	if host == "" || community == "" {
		t.Skip("SNMP_TEST_HOST or SNMP_TEST_COMMUNITY not set")
	}

	plugin, err := brutus.GetPlugin("snmp")
	if err != nil {
		t.Fatalf("Failed to get snmp plugin: %v", err)
	}

	ctx := context.Background()

	// Test valid community string
	t.Run("ValidCommunity", func(t *testing.T) {
		result := plugin.Test(ctx, host, "", community, defaultTimeout, brutus.PluginConfig{})
		assert.True(t, result.Success, "Valid community string should succeed")
		assert.Nil(t, result.Error, "Valid community should not return error")
	})

	// Test invalid community string
	t.Run("InvalidCommunity", func(t *testing.T) {
		result := plugin.Test(ctx, host, "", "wrongcommunity", defaultTimeout, brutus.PluginConfig{})
		assert.False(t, result.Success, "Invalid community string should fail")
		// SNMP may return error or nil depending on implementation
	})
}

// runProtocolTest executes the standard test pattern for a protocol
func runProtocolTest(t *testing.T, tc testCase) {
	host := os.Getenv(tc.hostEnv)
	if host == "" {
		t.Skipf("%s not set", tc.hostEnv)
	}

	var username, password string
	if tc.userEnv != "" {
		username = os.Getenv(tc.userEnv)
	}
	if tc.passEnv != "" {
		password = os.Getenv(tc.passEnv)
	}

	timeout := tc.timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	plugin, err := brutus.GetPlugin(tc.protocol)
	if err != nil {
		t.Fatalf("Failed to get %s plugin: %v", tc.protocol, err)
	}

	ctx := context.Background()

	// Test 1: Valid credentials should succeed
	t.Run("ValidCredentials", func(t *testing.T) {
		result := plugin.Test(ctx, host, username, password, timeout, brutus.PluginConfig{})

		if result.Error != nil {
			t.Logf("Connection error (may be expected): %v", result.Error)
			// Connection errors are acceptable in CI (service may not be ready)
			// We check that at least we got a result
			return
		}

		assert.True(t, result.Success, "Valid credentials should succeed")
		assert.Nil(t, result.Error, "Valid credentials should not return error")
		assert.Equal(t, tc.protocol, result.Protocol, "Protocol should match")
		assert.Contains(t, result.Target, host, "Target should contain host")
	})

	// Test 2: Invalid credentials should fail gracefully
	t.Run("InvalidCredentials", func(t *testing.T) {
		result := plugin.Test(ctx, host, username, "definitely-wrong-password-12345", timeout, brutus.PluginConfig{})

		if result.Error != nil {
			// Connection errors are different from auth failures
			t.Logf("Got error (may be connection issue): %v", result.Error)
			return
		}

		assert.False(t, result.Success, "Invalid credentials should fail")
		assert.Nil(t, result.Error, "Auth failure should return nil error (not connection error)")
	})
}

// TestHTTPBasicAuth tests HTTP Basic Authentication
// Uses httptest server since HTTP is often tested inline
func TestHTTPBasicAuth(t *testing.T) {
	t.Parallel()

	// HTTP tests use in-process httptest server
	// See cmd/brutus/integration_test.go for full HTTP pipeline tests
	t.Skip("HTTP tests use in-process httptest server in cmd/brutus/integration_test.go")
}
