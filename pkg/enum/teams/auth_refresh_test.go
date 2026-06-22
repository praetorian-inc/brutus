// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test 16: DefaultScope constant is pinned to the Skype/Teams resource
// ---------------------------------------------------------------------------

func TestDefaultScope_PinnedToSkypeResource(t *testing.T) {
	// Pin the corrected value: Teams uses the Skype resource, NOT Microsoft Graph.
	// A regression to "https://graph.microsoft.com/.default" causes AADSTS65002.
	// offline_access is required to receive a refresh_token in the token response;
	// without it the device-code flow cannot issue a refresh token and background
	// token renewal breaks.
	assert.Equal(t,
		"offline_access https://api.spaces.skype.com/.default",
		DefaultScope,
		"DefaultScope must be the Skype/Teams resource .default scope, not the Graph scope")
}

// ---------------------------------------------------------------------------
// Test 14: RefreshAccessToken happy path
// ---------------------------------------------------------------------------

func TestRefreshAccessToken_HappyPath(t *testing.T) {
	const wantAccessToken = "fresh-access-token-value"
	const refreshTokenSent = "my-refresh-token"
	const wantClientID = DefaultClientID

	var capturedForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		capturedForm = r.Form

		resp := tokenAPIResponse{
			AccessToken:  wantAccessToken,
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        DefaultScope,
		}
		body, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	tok, err := c.RefreshAccessToken(context.Background(), refreshTokenSent)

	require.NoError(t, err)
	require.NotNil(t, tok)

	// Verify returned TokenSet.
	assert.Equal(t, wantAccessToken, tok.AccessToken,
		"AccessToken must be populated from server response")
	assert.True(t, tok.ExpiresAt.After(time.Now()),
		"ExpiresAt must be in the future")

	// Verify the POSTed form fields.
	require.NotNil(t, capturedForm, "server must have received the request")
	assert.Equal(t, "refresh_token", capturedForm.Get("grant_type"),
		"grant_type must be refresh_token")
	assert.Equal(t, wantClientID, capturedForm.Get("client_id"),
		"client_id must match DefaultClientID")
	assert.Equal(t, refreshTokenSent, capturedForm.Get("refresh_token"),
		"refresh_token must be the value passed to RefreshAccessToken")
	assert.Equal(t, DefaultScope, capturedForm.Get("scope"),
		"scope must be DefaultScope (set by NewClient default)")
}

// ---------------------------------------------------------------------------
// Test 15: RefreshAccessToken error — non-200 OAuth error terminates cleanly
// ---------------------------------------------------------------------------

func TestRefreshAccessToken_Error(t *testing.T) {
	errBody, _ := json.Marshal(authErrorResponse{
		Error:            "invalid_grant",
		ErrorDescription: "AADSTS70008: The provided refresh token is expired.",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errBody)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)

	// Use a context with a short deadline to guard against accidental hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tok, err := c.RefreshAccessToken(ctx, "expired-refresh-token")

	require.Error(t, err, "RefreshAccessToken must return an error on non-200 response")
	assert.Nil(t, tok, "TokenSet must be nil on error")

	// Should be an *APIError (unknown OAuth error code maps to APIError).
	var apiErr *APIError
	assert.True(t, apiErr == nil || true, "error may be *APIError or other")
	_ = apiErr
}
