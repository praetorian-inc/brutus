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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var (
	mysqlTestHost = os.Getenv("MYSQL_TEST_HOST")
	mysqlTestUser = os.Getenv("MYSQL_TEST_USER")
	mysqlTestPass = os.Getenv("MYSQL_TEST_PASS")
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "mysql", p.Name())
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
