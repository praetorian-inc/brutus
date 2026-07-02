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

package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Tenant discovery tests
// ---------------------------------------------------------------------------

func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp := oidcConfig{Issuer: "https://acme.okta.com/oauth2/default"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestCheckTenant_Found(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@acme.com")

	require.NoError(t, result.Error)
	assert.True(t, result.HasTenant)
	assert.Contains(t, result.TenantURL, srv.URL)
	assert.Equal(t, DiscoveryDirect, result.DiscoveryMethod)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheckTenant_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@notkta.com")

	require.NoError(t, result.Error)
	assert.False(t, result.HasTenant)
	assert.Empty(t, result.TenantURL)
}

func TestCheckTenant_Forbidden(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@blocked.com")

	require.NoError(t, result.Error)
	assert.False(t, result.HasTenant)
}

func TestCheckTenant_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@broken.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected status")
	assert.False(t, result.HasTenant)
}

func TestCheckTenant_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not json`))
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@badjson.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "decoding response")
}

func TestCheckTenant_EmptyIssuer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcConfig{Issuer: ""})
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(context.Background(), "user@empty.com")

	require.NoError(t, result.Error)
	assert.False(t, result.HasTenant)
}

func TestCheckTenant_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewChecker(srv.URL+"/%s", 5*time.Second)
	result := c.CheckTenant(ctx, "user@acme.com")

	require.Error(t, result.Error)
	assert.False(t, result.HasTenant)
}

func TestCheckTenant_InvalidEmail(t *testing.T) {
	t.Parallel()
	c := NewChecker("", 5*time.Second)
	result := c.CheckTenant(context.Background(), "not-an-email")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "cannot derive tenant slug")
	assert.False(t, result.HasTenant)
}

func TestNewChecker_DefaultBaseURL(t *testing.T) {
	t.Parallel()
	c := NewChecker("", 5*time.Second)
	assert.Equal(t, DefaultBaseURL, c.baseURLFmt)
}

func Test_slugFromEmail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		email string
		want  string
	}{
		{"user@acme.com", "acme"},
		{"user@some-corp.co.uk", "some-corp"},
		{"user@UPPER.org", "upper"},
		{"user@mail.acme.com", "acme"},
		{"user@sub.domain.acme.co.uk", "acme"},
		{"user@single", ""},
		{"no-at-sign", ""},
		{"", ""},
		{"user@.com", ""},
	}
	for _, tc := range tests {
		t.Run(tc.email, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, slugFromEmail(tc.email))
		})
	}
}

// ---------------------------------------------------------------------------
// Federation discovery tests
// ---------------------------------------------------------------------------

func TestCheckTenantByURL_Found(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker("", 5*time.Second)
	result := c.CheckTenantByURL(context.Background(), srv.URL, DiscoveryFederationM365)

	require.NoError(t, result.Error)
	assert.True(t, result.HasTenant)
	assert.Equal(t, srv.URL, result.TenantURL)
	assert.Equal(t, DiscoveryFederationM365, result.DiscoveryMethod)
}

func TestCheckTenantByURL_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := NewChecker("", 5*time.Second)
	result := c.CheckTenantByURL(context.Background(), srv.URL, DiscoveryFederationGoogle)

	require.NoError(t, result.Error)
	assert.False(t, result.HasTenant)
	assert.Equal(t, DiscoveryFederationGoogle, result.DiscoveryMethod)
}

func TestCheckTenantByURL_TrailingSlash(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker("", 5*time.Second)
	result := c.CheckTenantByURL(context.Background(), srv.URL+"/", DiscoveryFederationM365)

	require.NoError(t, result.Error)
	assert.True(t, result.HasTenant)
	assert.False(t, strings.HasSuffix(result.TenantURL, "/"))
}

// ---------------------------------------------------------------------------
// ParseOktaTenantURL tests
// ---------------------------------------------------------------------------

func TestParseOktaTenantURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"full URL", "https://acme.okta.com/app/microsoft_office365/abc123/sso/saml", "https://acme.okta.com"},
		{"base URL", "https://acme.okta.com", "https://acme.okta.com"},
		{"preview URL", "https://acme.oktapreview.com/app/something", "https://acme.oktapreview.com"},
		{"bare host", "acme.okta.com", "https://acme.okta.com"},
		{"bare preview host", "acme.oktapreview.com", "https://acme.oktapreview.com"},
		{"not okta", "https://login.microsoftonline.com/abc", ""},
		{"empty", "", ""},
		{"non-okta host", "adfs.acme.com", ""},
		{"http scheme", "http://acme.okta.com", "http://acme.okta.com"},
		{"uppercase", "ACME.OKTA.COM", "https://ACME.OKTA.COM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ParseOktaTenantURL(tc.input))
		})
	}
}
