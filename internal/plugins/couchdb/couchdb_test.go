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

package couchdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var (
	couchdbTestHost = os.Getenv("COUCHDB_TEST_HOST")
	couchdbTestUser = os.Getenv("COUCHDB_TEST_USER")
	couchdbTestPass = os.Getenv("COUCHDB_TEST_PASS")
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "couchdb", p.Name())
}

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	if couchdbTestHost == "" {
		t.Skip("Integration test - requires CouchDB server (set COUCHDB_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, couchdbTestHost, couchdbTestUser, couchdbTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "couchdb", result.Protocol)
	assert.Equal(t, couchdbTestHost, result.Target)
	assert.Equal(t, couchdbTestUser, result.Username)
	assert.Equal(t, couchdbTestPass, result.Password)
	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	if couchdbTestHost == "" {
		t.Skip("Integration test - requires CouchDB server (set COUCHDB_TEST_HOST)")
	}

	p := &Plugin{}
	ctx := context.Background()

	result := p.Test(ctx, couchdbTestHost, couchdbTestUser, "definitely-wrong-password", 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "couchdb", result.Protocol)
	assert.Equal(t, couchdbTestHost, result.Target)
	assert.Equal(t, couchdbTestUser, result.Username)
	assert.Equal(t, "definitely-wrong-password", result.Password)
	assert.False(t, result.Success)
	assert.Nil(t, result.Error) // Auth failure returns nil error
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "127.0.0.1:1", "admin", "password", 2*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.Equal(t, "couchdb", result.Protocol)
	assert.Equal(t, "127.0.0.1:1", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error) // Connection error returns wrapped error
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_ContextCancellation(t *testing.T) {
	if couchdbTestHost == "" {
		t.Skip("Integration test - requires CouchDB server (set COUCHDB_TEST_HOST)")
	}

	p := &Plugin{}
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	result := p.Test(ctx, couchdbTestHost, couchdbTestUser, couchdbTestPass, 5*time.Second, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "198.51.100.1:5984", "admin", "password", 500*time.Millisecond, brutus.PluginConfig{})

	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MockValidCredentials(t *testing.T) {
	addr := mockCouchSession(t, http.StatusOK)
	r := (&Plugin{}).Test(context.Background(), addr, "admin", "secret", 2*time.Second, brutus.PluginConfig{})
	assert.True(t, r.Success)
	assert.Nil(t, r.Error)
}

func TestPlugin_Test_MockInvalidCredentials(t *testing.T) {
	addr := mockCouchSession(t, http.StatusOK)
	r := (&Plugin{}).Test(context.Background(), addr, "admin", "wrong", 2*time.Second, brutus.PluginConfig{})
	assert.False(t, r.Success)
	assert.Nil(t, r.Error)
}

func mockCouchSession(t *testing.T, okCode int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/_session" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(okCode)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}
