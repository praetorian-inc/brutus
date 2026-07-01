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

package microsoft365

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/common/GetCredentialType" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req credTypeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var resp credTypeResponse
		switch req.Username {
		case "exists@example.com":
			resp = credTypeResponse{IfExistsResult: 0}
		case "notexists@example.com":
			resp = credTypeResponse{IfExistsResult: 1}
		case "difftenant@example.com":
			resp = credTypeResponse{IfExistsResult: 5}
		case "domainhint@example.com":
			resp = credTypeResponse{IfExistsResult: 6}
		case "unknown@example.com":
			resp = credTypeResponse{IfExistsResult: 99}
		case "throttled@example.com":
			resp = credTypeResponse{IfExistsResult: 0, ThrottleStatus: 1}
		case "federated@example.com":
			resp = credTypeResponse{
				IfExistsResult:       0,
				FederationRedirectUrl: "https://adfs.example.com/adfs/ls/",
			}
		default:
			resp = credTypeResponse{IfExistsResult: 1}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestCheckAccount_Exists(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "exists@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultExists, result.IfExistsResult)
	assert.False(t, result.Federated)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheckAccount_NotExists(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "notexists@example.com")

	require.NoError(t, result.Error)
	assert.False(t, result.Exists)
	assert.Equal(t, IfExistsResultNotExists, result.IfExistsResult)
}

func TestCheckAccount_DifferentTenant(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "difftenant@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultDifferentTenant, result.IfExistsResult)
}

func TestCheckAccount_DomainHint(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "domainhint@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultDomainHint, result.IfExistsResult)
}

func TestCheckAccount_UnknownResult(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "unknown@example.com")

	require.NoError(t, result.Error)
	assert.False(t, result.Exists)
	assert.Equal(t, 99, result.IfExistsResult)
}

func TestCheckAccount_Throttled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "throttled@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "throttled")
	assert.False(t, result.Exists)
}

func TestCheckAccount_Federated(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "federated@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.True(t, result.Federated)
	assert.Equal(t, "https://adfs.example.com/adfs/ls/", result.FederationURL)
}

func TestCheckAccount_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "test@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected status")
}

func TestCheckAccount_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	t.Cleanup(srv.Close)

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(context.Background(), "test@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "decoding response")
}

func TestCheckAccount_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewChecker(srv.URL, 5*time.Second)
	result := c.CheckAccount(ctx, "exists@example.com")

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
}

func TestNewChecker_DefaultBaseURL(t *testing.T) {
	t.Parallel()
	c := NewChecker("", 5*time.Second)
	assert.Equal(t, DefaultBaseURL, c.baseURL)
}
