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

package postgresql

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// getTestConfig returns test configuration from environment variables with defaults
func getTestConfig() (host, user, pass string) {
	host = os.Getenv("POSTGRES_TEST_HOST")
	if host == "" {
		host = "localhost:5432"
	}
	user = os.Getenv("POSTGRES_TEST_USER")
	if user == "" {
		user = "postgres"
	}
	pass = os.Getenv("POSTGRES_TEST_PASS")
	if pass == "" {
		pass = "postgres"
	}
	return
}

func TestPostgresURL(t *testing.T) {
	t.Run("special chars in password", func(t *testing.T) {
		s := postgresURL("db.example.com", "5432", "user", `p@ss word'`, "disable", time.Second)
		u, err := url.Parse(s)
		require.NoError(t, err)
		pass, ok := u.User.Password()
		require.True(t, ok)
		assert.Equal(t, `p@ss word'`, pass)
		assert.Equal(t, "user", u.User.Username())
		assert.Equal(t, "db.example.com:5432", u.Host)
		assert.Equal(t, "/postgres", u.Path)
		assert.Equal(t, "disable", u.Query().Get("sslmode"))
		assert.Equal(t, "1", u.Query().Get("connect_timeout"))
	})
	t.Run("IPv6", func(t *testing.T) {
		s := postgresURL("::1", "5432", "postgres", "x", "disable", time.Second)
		u, err := url.Parse(s)
		require.NoError(t, err)
		assert.Equal(t, "[::1]:5432", u.Host)
	})
	t.Run("subsecond timeout floors to 1s", func(t *testing.T) {
		s := postgresURL("h", "5432", "u", "p", "disable", 200*time.Millisecond)
		u, err := url.Parse(s)
		require.NoError(t, err)
		assert.Equal(t, "1", u.Query().Get("connect_timeout"))
	})
	t.Run("skip-verify sslmode", func(t *testing.T) {
		s := postgresURL("h", "5432", "u", "p", "skip-verify", time.Second)
		u, err := url.Parse(s)
		require.NoError(t, err)
		assert.Equal(t, "pqgo-brutus-skip-verify", u.Query().Get("sslmode"))
	})
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "postgresql", p.Name())
}

func TestSSLMode(t *testing.T) {
	tests := []struct {
		tlsMode string
		want    string
	}{
		{"verify", "verify-full"},
		{"skip-verify", "pqgo-brutus-skip-verify"},
		{"disable", "disable"},
		{"", "disable"},
	}

	for _, tt := range tests {
		t.Run(tt.tlsMode, func(t *testing.T) {
			assert.Equal(t, tt.want, sslMode(tt.tlsMode))
		})
	}
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool // true if should be classified as auth error (nil)
	}{
		{
			name:     "password authentication failed",
			errStr:   "password authentication failed for user \"postgres\"",
			wantAuth: true,
		},
		{
			name:     "role does not exist",
			errStr:   "role \"baduser\" does not exist",
			wantAuth: true,
		},
		{
			// "database X does not exist" is returned AFTER successful
			// authentication, so it must NOT be classified as invalid
			// credentials (doing so silently discards valid credentials).
			name:     "database does not exist is post-auth, not invalid creds",
			errStr:   "database \"postgres\" does not exist",
			wantAuth: false,
		},
		{
			// "permission denied for database X" is an authorization error
			// that only occurs AFTER successful authentication. Classifying
			// it as invalid credentials would silently discard VALID creds.
			name:     "permission denied is post-auth, not invalid creds",
			errStr:   "pq: permission denied for database \"postgres\"",
			wantAuth: false,
		},
		{
			name:     "no pg_hba.conf entry",
			errStr:   "no pg_hba.conf entry for host \"127.0.0.1\"",
			wantAuth: true,
		},
		{
			name:     "bare does not exist is not auth",
			errStr:   "relation \"foo\" does not exist",
			wantAuth: false,
		},
		{
			name:     "connection error",
			errStr:   "connection refused",
			wantAuth: false,
		},
		{
			name:     "network error",
			errStr:   "no route to host",
			wantAuth: false,
		},
		{
			name:     "timeout error",
			errStr:   "context deadline exceeded",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &mockError{msg: tt.errStr}
			result := classifyError(err)

			if tt.wantAuth {
				assert.Nil(t, result, "auth errors should return nil")
			} else {
				assert.NotNil(t, result, "connection errors should be wrapped")
				assert.Contains(t, result.Error(), "connection error")
			}
		})
	}
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	host, user, pass := getTestConfig()
	if os.Getenv("POSTGRES_TEST_HOST") == "" {
		t.Skip("Integration test - requires PostgreSQL server (set POSTGRES_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, pass, result.Password)
	assert.True(t, result.Success, "Expected successful authentication")
	assert.Nil(t, result.Error, "Expected no error on successful auth")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	host, user, _ := getTestConfig()
	if os.Getenv("POSTGRES_TEST_HOST") == "" {
		t.Skip("Integration test - requires PostgreSQL server (set POSTGRES_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()
	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, "definitely-wrong-password", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, host, result.Target)
	assert.Equal(t, user, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success, "Expected failed authentication")
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use a port that should not have PostgreSQL running
	result := p.Test(ctx, "localhost:9999", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "Connection error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Use an invalid hostname
	result := p.Test(ctx, "127.0.0.1:1", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success, "Expected connection failure")
	assert.NotNil(t, result.Error, "DNS error should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Very short timeout to force timeout error
	timeout := 1 * time.Nanosecond

	result := p.Test(ctx, "localhost:5432", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected timeout failure")
	assert.NotNil(t, result.Error, "Timeout should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	host, user, pass := getTestConfig()
	if os.Getenv("POSTGRES_TEST_HOST") == "" {
		t.Skip("Integration test - requires PostgreSQL server (set POSTGRES_TEST_HOST)")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	timeout := 5 * time.Second

	result := p.Test(ctx, host, user, pass, timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success, "Expected context cancellation failure")
	assert.NotNil(t, result.Error, "Context cancellation should have non-nil error")
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_CanceledContextNoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := (&Plugin{}).Test(ctx, "127.0.0.1:1", "postgres", "x", time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.NotNil(t, r.Error)
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()
	timeout := 2 * time.Second

	// Target without port (should use default or fail)
	result := p.Test(ctx, "localhost", "postgres", "postgres", timeout, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "postgresql", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	// Connection may fail or succeed depending on implementation
	// Just verify we get a valid result structure
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestScrubError(t *testing.T) {
	const password = "s3cret-pass"
	dsn := postgresURL("h", "5432", "u", password, "disable", time.Second)

	t.Run("redacts dsn and password", func(t *testing.T) {
		err := errors.New("failed using " + dsn + " password=" + password)
		got := scrubError(err, dsn, password)
		require.NotNil(t, got)
		assert.NotContains(t, got.Error(), password)
		assert.NotContains(t, got.Error(), dsn)
		assert.Contains(t, got.Error(), "REDACTED")
	})

	t.Run("unchanged when nothing to redact", func(t *testing.T) {
		err := errors.New("connection refused")
		got := scrubError(err, dsn, password)
		assert.Equal(t, err, got)
	})

	t.Run("auth classification still works after scrub", func(t *testing.T) {
		err := errors.New("password authentication failed for user \"u\"")
		assert.Nil(t, classifyError(scrubError(err, dsn, password)))
	})
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	p := &Plugin{}
	result := p.Test(context.Background(), "127.0.0.1:5432", "postgres", "s3cret-pass", time.Second, brutus.PluginConfig{
		ProxyURL: "http://127.0.0.1:1",
	})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.NotContains(t, result.Error.Error(), "s3cret-pass")
}

func TestInit(t *testing.T) {
	// Verify that init() registered this plugin with the global registry
	// under the name "postgresql", so brutus.GetPlugin("postgresql") resolves it.
	p, err := brutus.GetPlugin("postgresql")
	require.NoError(t, err, "postgresql plugin must be registered via init()")
	assert.Equal(t, "postgresql", p.Name())
}

// mockError is a simple error implementation for testing error classification
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
