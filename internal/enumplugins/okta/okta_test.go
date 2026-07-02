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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

func TestName(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	assert.Equal(t, "okta", p.Name())
}

// newMockOktaServer simulates Okta's well-known OIDC endpoint.
func newMockOktaServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/acme/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": "https://acme.okta.com",
			})
		case "/notfound/.well-known/openid-configuration":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func TestCheck_TenantFound(t *testing.T) {
	t.Parallel()
	srv := newMockOktaServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURLFmt: srv.URL + "/%s"}
	result := p.Check(context.Background(), "user@acme.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "tenant found should set Exists=true")
	assert.Equal(t, enum.ConfidenceLow, result.Confidence, "tenant-only signal should be low confidence")
	assert.Equal(t, "okta", result.Service)
	assert.Equal(t, "user@acme.com", result.Email)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheck_TenantNotFound(t *testing.T) {
	t.Parallel()
	srv := newMockOktaServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURLFmt: srv.URL + "/%s"}
	result := p.Check(context.Background(), "user@notfound.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "no tenant should set Exists=false")
	assert.Equal(t, enum.ConfidenceLow, result.Confidence, "slug heuristic is unreliable, so no-tenant should be low confidence")
}

func TestCheck_ServerError(t *testing.T) {
	t.Parallel()
	srv := newMockOktaServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURLFmt: srv.URL + "/%s"}
	result := p.Check(context.Background(), "user@servererr.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
	assert.Contains(t, result.Error.Error(), "unexpected status")
}

func TestCheck_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockOktaServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &Plugin{baseURLFmt: srv.URL + "/%s"}
	result := p.Check(ctx, "user@acme.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
}
