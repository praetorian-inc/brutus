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

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// newMockMicrosoftServer creates an httptest.Server that simulates the
// Microsoft 365 GetCredentialType API. The email in the request body
// drives which response is returned.
func newMockMicrosoftServer(t *testing.T) *httptest.Server {
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
			resp = credTypeResponse{IfExistsResult: 0, ThrottleStatus: 0}
		case "notexists@example.com":
			resp = credTypeResponse{IfExistsResult: 1, ThrottleStatus: 0}
		case "difftenant@example.com":
			resp = credTypeResponse{IfExistsResult: 5, ThrottleStatus: 0}
		case "domainhint@example.com":
			resp = credTypeResponse{IfExistsResult: 6, ThrottleStatus: 0}
		case "unknown@example.com":
			resp = credTypeResponse{IfExistsResult: 99, ThrottleStatus: 0}
		case "throttled@example.com":
			resp = credTypeResponse{IfExistsResult: 0, ThrottleStatus: 1}
		default:
			resp = credTypeResponse{IfExistsResult: 1, ThrottleStatus: 0}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestCheck_UserExists(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "exists@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "IfExistsResult=0 should indicate account exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
	assert.Equal(t, "microsoft365", result.Service)
	assert.Equal(t, "exists@example.com", result.Email)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheck_UserNotExists(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "notexists@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "IfExistsResult=1 should indicate account does not exist")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

func TestCheck_DifferentTenant(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "difftenant@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "IfExistsResult=5 (different tenant) should indicate exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

func TestCheck_DomainHint(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "domainhint@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "IfExistsResult=6 (domain hint) should indicate exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

func TestCheck_UnknownResult(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "unknown@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "IfExistsResult=99 (unknown) should not indicate exists")
	assert.Equal(t, enum.ConfidenceLow, result.Confidence)
}

func TestCheck_Throttled(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "throttled@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "throttled")
	assert.False(t, result.Exists)
}

func TestCheck_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "test@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "decoding response")
}

func TestCheck_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "test@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected status")
}

func TestCheck_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockMicrosoftServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(ctx, "exists@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
}

func TestCheck_RequestBody(t *testing.T) {
	t.Parallel()
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = body
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(credTypeResponse{IfExistsResult: 0, ThrottleStatus: 0})
	}))
	t.Cleanup(srv.Close)

	p := &Plugin{baseURL: srv.URL}
	_ = p.Check(context.Background(), "verify@example.com", 5*time.Second)

	var req credTypeRequest
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	assert.Equal(t, "verify@example.com", req.Username, "request body should contain the email as Username")
}

func TestName(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	assert.Equal(t, "microsoft365", p.Name())
}
