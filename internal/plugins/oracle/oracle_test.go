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

package oracle

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func getTestConfig() (host, user, pass string) {
	host = os.Getenv("ORACLE_TEST_HOST")
	if host == "" {
		host = "localhost:1521"
	}
	user = os.Getenv("ORACLE_TEST_USER")
	if user == "" {
		user = "system"
	}
	pass = os.Getenv("ORACLE_TEST_PASS")
	if pass == "" {
		pass = "oracle"
	}
	return
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "oracle", p.Name())
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		wantAuth bool // true = auth failure (nil error), false = connection error
	}{
		{
			name:     "ORA-01017 invalid credentials",
			errStr:   "ORA-01017: invalid username/password; logon denied",
			wantAuth: true,
		},
		{
			name:     "ORA-28000 account locked",
			errStr:   "ORA-28000: the account is locked",
			wantAuth: true,
		},
		{
			name:     "ORA-01005 null password",
			errStr:   "ORA-01005: null password given; logon denied",
			wantAuth: true,
		},
		{
			name:     "connection refused",
			errStr:   "connection refused",
			wantAuth: false,
		},
		{
			name:     "network unreachable",
			errStr:   "no route to host",
			wantAuth: false,
		},
		{
			name:     "timeout",
			errStr:   "context deadline exceeded",
			wantAuth: false,
		},
		{
			name:     "TNS no listener",
			errStr:   "ORA-12541: TNS:no listener",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyError(&mockError{msg: tt.errStr})

			if tt.wantAuth {
				assert.Nil(t, err, "auth failure errors should return nil")
			} else {
				assert.NotNil(t, err, "connection errors should be wrapped")
				assert.Contains(t, err.Error(), "connection error")
			}
		})
	}
}

func TestIsAuthSuccess(t *testing.T) {
	tests := []struct {
		name    string
		errStr  string
		wantHit bool
	}{
		{
			name:    "ORA-28001 password expired",
			errStr:  "ORA-28001: the password has expired",
			wantHit: true,
		},
		{
			name:    "ORA-28009 SYS privilege",
			errStr:  "ORA-28009: connection as SYS should be as SYSDBA or SYSOPER",
			wantHit: true,
		},
		{
			name:    "ORA-01031 insufficient privileges",
			errStr:  "ORA-01031: insufficient privileges",
			wantHit: true,
		},
		{
			name:    "ORA-01017 wrong password",
			errStr:  "ORA-01017: invalid username/password; logon denied",
			wantHit: false,
		},
		{
			name:    "connection refused",
			errStr:  "connection refused",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAuthSuccess(&mockError{msg: tt.errStr})
			assert.Equal(t, tt.wantHit, result)
		})
	}
}

func TestDefaultServiceNames(t *testing.T) {
	assert.NotEmpty(t, defaultServiceNames, "should have default service names")
	assert.Contains(t, defaultServiceNames, "XE")
	assert.Contains(t, defaultServiceNames, "ORCL")
}

func TestPlugin_Test_ConnectionRefused(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:9999", "system", "oracle", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "oracle", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidTarget(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "127.0.0.1:1", "system", "oracle", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "oracle", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ResultStructure(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost:9999", "user", "pass", 100*time.Millisecond, brutus.PluginConfig{})

	assert.Equal(t, "oracle", result.Protocol)
	assert.Equal(t, "localhost:9999", result.Target)
	assert.Equal(t, "user", result.Username)
	assert.Equal(t, "pass", result.Password)
	assert.False(t, result.Success)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_MissingPort(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, "localhost", "system", "oracle", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "oracle", result.Protocol)
	assert.Equal(t, "localhost", result.Target)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := p.Test(ctx, "localhost:1521", "system", "oracle", time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	host, user, pass := getTestConfig()
	if os.Getenv("ORACLE_TEST_HOST") == "" {
		t.Skip("Integration test - requires Oracle server (set ORACLE_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, host, user, pass, 10*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "oracle", result.Protocol)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	host, user, _ := getTestConfig()
	if os.Getenv("ORACLE_TEST_HOST") == "" {
		t.Skip("Integration test - requires Oracle server (set ORACLE_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, host, user, "wrongpassword", 10*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error, "Authentication failure should have nil error")
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
