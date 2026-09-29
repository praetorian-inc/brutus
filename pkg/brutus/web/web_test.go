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

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestIsWebProtocol(t *testing.T) {
	// Web protocols (should return true)
	assert.True(t, IsWebProtocol("http"))
	assert.True(t, IsWebProtocol("https"))
	assert.True(t, IsWebProtocol("browser"))

	// Non-web protocols (should return false)
	assert.False(t, IsWebProtocol("ssh"))
	assert.False(t, IsWebProtocol("mysql"))
	assert.False(t, IsWebProtocol("rdp"))
	assert.False(t, IsWebProtocol("snmp"))
	assert.False(t, IsWebProtocol("ldap"))
	assert.False(t, IsWebProtocol("ftp"))
	assert.False(t, IsWebProtocol(""))
}

func TestIsWebProtocol_ComplementsCreds(t *testing.T) {
	// Every protocol should be web XOR creds — verify no overlap and no gaps
	// for the protocols both packages know about.
	webProtos := []string{"http", "https", "browser"}
	credsProtos := []string{"ssh", "mysql", "rdp", "snmp", "ldap", "ftp", "smb"}

	for _, p := range webProtos {
		assert.True(t, IsWebProtocol(p), "expected web protocol: %s", p)
	}
	for _, p := range credsProtos {
		assert.False(t, IsWebProtocol(p), "expected non-web protocol: %s", p)
	}
}

func TestNewBrowserPlugin_ReturnsPlugin(t *testing.T) {
	plugin := NewBrowserPlugin(3, 60000000000, false, false)
	assert.NotNil(t, plugin)
	assert.Equal(t, "browser", plugin.Name())
}

func TestConfigureAICredentials_AddsAdminFallback(t *testing.T) {
	aiCreds := []brutus.Credential{
		{Username: "root", Password: "toor"},
	}
	result := ConfigureAICredentials(aiCreds)

	assert.Len(t, result, 2)
	assert.Equal(t, "root", result[0].Username)
	assert.Equal(t, "toor", result[0].Password)
	assert.Equal(t, "admin", result[1].Username)
	assert.Equal(t, "admin", result[1].Password)
}

func TestConfigureAICredentials_EmptyInput(t *testing.T) {
	result := ConfigureAICredentials(nil)

	assert.Len(t, result, 1)
	assert.Equal(t, "admin", result[0].Username)
	assert.Equal(t, "admin", result[0].Password)
}

func TestConfigureAICredentials_PreservesOrder(t *testing.T) {
	aiCreds := []brutus.Credential{
		{Username: "user1", Password: "pass1"},
		{Username: "user2", Password: "pass2"},
		{Username: "user3", Password: "pass3"},
	}
	result := ConfigureAICredentials(aiCreds)

	assert.Len(t, result, 4)
	// AI creds come first, admin:admin last
	for i, c := range aiCreds {
		assert.Equal(t, c.Username, result[i].Username)
		assert.Equal(t, c.Password, result[i].Password)
	}
	assert.Equal(t, "admin", result[3].Username)
}

// TestRouteHTTP_FailsClosedOnDetectionError verifies the security fix: when
// DetectHTTPAuthType cannot probe the target (unreachable host / error, which
// returns an empty authType), RouteHTTP must preserve the original protocol
// rather than routing to the proxy-bypassing "browser" plugin.
func TestRouteHTTP_FailsClosedOnDetectionError(t *testing.T) {
	// 127.0.0.1:1 refuses connections, so DetectHTTPAuthType returns "".
	protocol, creds := RouteHTTP(context.Background(), "127.0.0.1:1", "http", 500*time.Millisecond, "", "", nil)

	assert.Equal(t, "http", protocol, "detection error must keep the original protocol, not switch to browser")
	assert.Nil(t, creds)
}

// TestRouteHTTP_RoutesFormToBrowser verifies that a positive form detection
// (HTTP 200 with no WWW-Authenticate header) still routes to the browser plugin.
func TestRouteHTTP_RoutesFormToBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><form></form></html>"))
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "http://")
	protocol, creds := RouteHTTP(context.Background(), target, "http", 2*time.Second, "", "", nil)

	assert.Equal(t, "browser", protocol, "an explicit form detection should route to the browser plugin")
	assert.Nil(t, creds)
}

func TestRouteHTTP_BasicAuthKeepsProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	target := strings.TrimPrefix(srv.URL, "http://")
	protocol, creds := RouteHTTP(context.Background(), target, "http", 2*time.Second, "", "", nil)

	assert.Equal(t, "http", protocol, "basic auth must keep the original protocol, not switch to browser")
	assert.Nil(t, creds, "nil LLM config must not invent credentials")
}

func TestResearchBrowserCredentials_DisabledLLM(t *testing.T) {
	creds, plug, err := ResearchBrowserCredentials(context.Background(), "example.com", BrowserConfig{})
	assert.NoError(t, err)
	assert.Nil(t, creds)
	assert.Nil(t, plug)

	creds, plug, err = ResearchBrowserCredentials(context.Background(), "example.com", BrowserConfig{
		LLMConfig: &brutus.LLMConfig{Enabled: false},
	})
	assert.NoError(t, err)
	assert.Nil(t, creds)
	assert.Nil(t, plug)
}
