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

package mysql

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var (
	mysqlTestHost = os.Getenv("MYSQL_TEST_HOST")
	mysqlTestUser = os.Getenv("MYSQL_TEST_USER")
	mysqlTestPass = os.Getenv("MYSQL_TEST_PASS")
)

func TestMySQLDSN(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		user     string
		pass     string
		tlsMode  string
		wantAddr string
		wantTLS  string
	}{
		{
			name:     "special chars in password",
			target:   "10.0.0.1:3306",
			user:     "root",
			pass:     "p@ss:word/x?",
			wantAddr: "10.0.0.1:3306",
			wantTLS:  "false",
		},
		{
			name:     "IPv6",
			target:   "::1",
			user:     "root",
			pass:     "x",
			wantAddr: "[::1]:3306",
			wantTLS:  "false",
		},
		{
			name:     "skip-verify",
			target:   "db.example.com",
			user:     "app",
			pass:     "secret",
			tlsMode:  "skip-verify",
			wantAddr: "db.example.com:3306",
			wantTLS:  "skip-verify",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := mysqlDSN(tt.target, tt.user, tt.pass, tt.tlsMode, "", time.Second)
			require.NoError(t, err)
			cfg, err := mysqldriver.ParseDSN(dsn)
			require.NoError(t, err)
			assert.Equal(t, tt.user, cfg.User)
			assert.Equal(t, tt.pass, cfg.Passwd)
			assert.Equal(t, "tcp", cfg.Net)
			assert.Equal(t, tt.wantAddr, cfg.Addr)
			assert.Equal(t, tt.wantTLS, cfg.TLSConfig)
		})
	}
}

func TestMySQLDSN_Proxy(t *testing.T) {
	proxyA := "socks5://127.0.0.1:1080"
	proxyB := "socks5h://127.0.0.1:1081"

	dsnA, err := mysqlDSN("10.0.0.1:3306", "root", "x", "", proxyA, time.Second)
	require.NoError(t, err)
	cfgA, err := mysqldriver.ParseDSN(dsnA)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:3306", cfgA.Addr)
	assert.True(t, cfgA.Net != "" && cfgA.Net != "tcp")
	assert.Equal(t, proxyNetName(proxyA), cfgA.Net)

	dsnA2, err := mysqlDSN("10.0.0.1:3306", "root", "x", "", proxyA, time.Second)
	require.NoError(t, err)
	cfgA2, err := mysqldriver.ParseDSN(dsnA2)
	require.NoError(t, err)
	assert.Equal(t, cfgA.Net, cfgA2.Net)

	dsnB, err := mysqlDSN("10.0.0.1:3306", "root", "x", "", proxyB, time.Second)
	require.NoError(t, err)
	cfgB, err := mysqldriver.ParseDSN(dsnB)
	require.NoError(t, err)
	assert.Equal(t, proxyNetName(proxyB), cfgB.Net)
	assert.NotEqual(t, cfgA.Net, cfgB.Net)

	_, err = mysqlDSN("10.0.0.1:3306", "root", "x", "", "ftp://127.0.0.1:9", time.Second)
	require.Error(t, err)
}

func TestPlugin_Test_InvalidProxy(t *testing.T) {
	p := &Plugin{}
	result := p.Test(context.Background(), "127.0.0.1:3306", "root", "x", time.Second, brutus.PluginConfig{
		ProxyURL: "ftp://127.0.0.1:9",
	})
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "mysql", p.Name())
}

func TestPlugin_Test_ErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool
	}{
		{name: "access denied", errStr: "Access denied for user 'root'", wantAuth: true},
		{name: "authentication failed", errStr: "authentication failed", wantAuth: true},
		{name: "timeout", errStr: "i/o timeout", wantAuth: false},
		{name: "connection refused", errStr: "connection refused", wantAuth: false},
		{name: "deadline exceeded", errStr: "context deadline exceeded", wantAuth: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyError(errors.New(tt.errStr))
			if tt.wantAuth {
				assert.Nil(t, result)
			} else {
				assert.ErrorContains(t, result, "connection error")
			}
		})
	}
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	if mysqlTestHost == "" {
		t.Skip("Integration test - requires MySQL server (set MYSQL_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, mysqlTestHost, mysqlTestUser, mysqlTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mysql", result.Protocol)
	assert.Equal(t, mysqlTestHost, result.Target)
	assert.Equal(t, mysqlTestUser, result.Username)
	assert.Equal(t, mysqlTestPass, result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	if mysqlTestHost == "" {
		t.Skip("Integration test - requires MySQL server (set MYSQL_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, mysqlTestHost, mysqlTestUser, "definitely-wrong-password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mysql", result.Protocol)
	assert.Equal(t, mysqlTestHost, result.Target)
	assert.Equal(t, mysqlTestUser, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "root", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "mysql", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if mysqlTestHost == "" {
		t.Skip("Integration test - requires MySQL server (set MYSQL_TEST_HOST)")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, mysqlTestHost, mysqlTestUser, mysqlTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:3306", "root", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}
