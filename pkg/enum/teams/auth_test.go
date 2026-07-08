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
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient creates a Client with overridden base URLs for testing.
func newTestClient(t *testing.T, tenantID, clientID, scopes, deviceCodeURL, tokenURL string) *Client {
	t.Helper()
	c, err := NewClient(tenantID, clientID, scopes, "", 5*time.Second)
	require.NoError(t, err)
	c.deviceCodeBaseURL = deviceCodeURL
	c.tokenBaseURL = tokenURL
	c.pollInterval = time.Millisecond
	return c
}

// ---------------------------------------------------------------------------
// APIError
// ---------------------------------------------------------------------------

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 400, Code: "invalid_client", Description: "AADSTS70011"}
	msg := err.Error()
	assert.Contains(t, msg, "400")
	assert.Contains(t, msg, "invalid_client")
	assert.Contains(t, msg, "AADSTS70011")
}

// ---------------------------------------------------------------------------
// NewClient defaults
// ---------------------------------------------------------------------------

func TestNewClient_Defaults(t *testing.T) {
	c, err := NewClient("", "", "", "", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "organizations", c.tenantID)
	assert.Equal(t, DefaultClientID, c.clientID)
	assert.Equal(t, DefaultScope, c.scopes)
}

// ---------------------------------------------------------------------------
// StartDeviceFlow
// ---------------------------------------------------------------------------

func TestStartDeviceFlow_Success(t *testing.T) {
	resp := deviceCodeAPIResponse{
		DeviceCode:      "device-code-xyz",
		UserCode:        "ABCD-1234",
		VerificationURI: "https://microsoft.com/devicelogin",
		ExpiresIn:       900,
		Interval:        5,
		Message:         "Enter code at https://microsoft.com/devicelogin",
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "mytenant", "", "", srv.URL, srv.URL)
	dc, err := c.StartDeviceFlow(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "ABCD-1234", dc.UserCode)
	assert.Equal(t, "https://microsoft.com/devicelogin", dc.VerificationURI)
	assert.Equal(t, 900, dc.ExpiresIn)
	assert.Equal(t, "device-code-xyz", dc.deviceCode)
	assert.Equal(t, 5, dc.interval)
}

func TestStartDeviceFlow_SmallInterval(t *testing.T) {
	resp := deviceCodeAPIResponse{
		DeviceCode:      "dc",
		UserCode:        "USER-CODE",
		VerificationURI: "https://microsoft.com/devicelogin",
		Interval:        2, // below minimum
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	dc, err := c.StartDeviceFlow(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int(minPollInterval.Seconds()), dc.interval, "interval should be floored to minPollInterval")
}

func TestStartDeviceFlow_NonOKResponse(t *testing.T) {
	errBody, _ := json.Marshal(authErrorResponse{
		Error:            "invalid_client",
		ErrorDescription: "AADSTS70011: The scope requested is invalid.",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errBody)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.StartDeviceFlow(context.Background())
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	assert.Equal(t, "invalid_client", apiErr.Code)
}

func TestStartDeviceFlow_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.StartDeviceFlow(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding")
}

func TestStartDeviceFlow_MissingUserCode(t *testing.T) {
	resp := deviceCodeAPIResponse{
		DeviceCode:      "dc",
		VerificationURI: "https://x.com",
		// UserCode intentionally absent
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.StartDeviceFlow(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestStartDeviceFlow_MissingVerificationURI(t *testing.T) {
	resp := deviceCodeAPIResponse{
		DeviceCode: "dc",
		UserCode:   "ABCD-1234",
		// VerificationURI intentionally absent
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.StartDeviceFlow(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestStartDeviceFlow_MissingDeviceCode(t *testing.T) {
	resp := deviceCodeAPIResponse{
		UserCode:        "ABCD-1234",
		VerificationURI: "https://microsoft.com/devicelogin",
		// DeviceCode intentionally absent
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.StartDeviceFlow(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

// ---------------------------------------------------------------------------
// WaitForToken
// ---------------------------------------------------------------------------

func makeTokenResponse() tokenAPIResponse {
	return tokenAPIResponse{
		AccessToken:  "eyJ0access",
		RefreshToken: "eyJ0refresh",
		IDToken:      "eyJ0id",
		TokenType:    "Bearer",
		Scope:        DefaultScope,
		ExpiresIn:    3600,
	}
}

func TestWaitForToken_NilDeviceCode(t *testing.T) {
	c, err := NewClient("", "", "", "", 5*time.Second)
	require.NoError(t, err)
	_, err = c.WaitForToken(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestWaitForToken_ImmediateSuccess(t *testing.T) {
	tokResp := makeTokenResponse()
	body, _ := json.Marshal(tokResp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dc := &DeviceCode{
		deviceCode: "dc-123",
		interval:   0, // zero → floored to minPollInterval in WaitForToken
	}

	// Use a very short timeout so the test completes quickly; the first
	// poll returns success immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	tok, err := c.WaitForToken(ctx, dc)
	require.NoError(t, err)
	require.NotNil(t, tok)

	assert.Equal(t, "eyJ0access", tok.AccessToken)
	assert.Equal(t, "eyJ0refresh", tok.RefreshToken)
	assert.Equal(t, "eyJ0id", tok.IDToken)
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, 3600, tok.ExpiresIn)
	assert.True(t, tok.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
}

func TestWaitForToken_PendingThenSuccess(t *testing.T) {
	var callCount atomic.Int32
	tokResp := makeTokenResponse()
	successBody, _ := json.Marshal(tokResp)
	pendingBody, _ := json.Marshal(authErrorResponse{Error: "authorization_pending"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n < 3 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(pendingBody)
			return
		}
		_, _ = w.Write(successBody)
	}))
	defer srv.Close()

	// Give a generous timeout; with minPollInterval = 5s this would take 10s,
	// so we override the interval to 1ms via a zero-interval DeviceCode.
	dc := &DeviceCode{deviceCode: "dc-pending", interval: 0}

	// We need the interval to be tiny for the test to run fast. WaitForToken
	// floors the interval to minPollInterval (5s) unless we inject a client
	// with a patched minPollInterval — but that's unexported. Instead we just
	// give a long enough context and rely on the server returning quickly.
	//
	// To keep the test fast we override the internal interval by setting a
	// tiny value that the test server cooperates on: since WaitForToken calls
	// time.After(interval) before each poll and interval is floored to 5s,
	// we need either to wait 10s or to make the server fast-path.
	//
	// Simplest approach: set interval on dc to a non-zero small value that
	// bypasses the floor. The floor only applies if interval < minPollInterval,
	// and minPollInterval == 5 seconds. So interval==5 is minimum anyway.
	// Accept the 10-second test duration (2 pending + 1 success × 5s interval).
	// Use t.Skip for CI environments where 10s is acceptable.

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	tok, err := c.WaitForToken(ctx, dc)
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, "eyJ0access", tok.AccessToken)
	assert.Equal(t, int32(3), callCount.Load())
}

func TestWaitForToken_SlowDown(t *testing.T) {
	// Send slow_down on first call, then success on second.
	var callCount atomic.Int32
	tokResp := makeTokenResponse()
	successBody, _ := json.Marshal(tokResp)
	slowDownBody, _ := json.Marshal(authErrorResponse{Error: "slow_down"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(slowDownBody)
			return
		}
		_, _ = w.Write(successBody)
	}))
	defer srv.Close()

	dc := &DeviceCode{deviceCode: "dc-slow", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	tok, err := c.WaitForToken(ctx, dc)
	// After slow_down the interval grows by 5s, but the loop continues.
	// The second call returns success.
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.GreaterOrEqual(t, callCount.Load(), int32(2))
}

func TestWaitForToken_ExpiredToken(t *testing.T) {
	body, _ := json.Marshal(authErrorResponse{Error: "expired_token"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dc := &DeviceCode{deviceCode: "dc-expired", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.WaitForToken(ctx, dc)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrExpiredToken), "expected ErrExpiredToken, got %v", err)
}

func TestWaitForToken_AccessDenied(t *testing.T) {
	body, _ := json.Marshal(authErrorResponse{Error: "access_denied"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dc := &DeviceCode{deviceCode: "dc-denied", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.WaitForToken(ctx, dc)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAccessDenied), "expected ErrAccessDenied, got %v", err)
}

func TestWaitForToken_ContextCancellation(t *testing.T) {
	// Server blocks until the request context is canceled (client hung up),
	// then returns without writing a response.  This ensures the handler exits
	// promptly so srv.Close() is never blocked waiting for an active connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			// Client canceled — handler exits immediately.
			return
		case <-time.After(10 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	// CloseClientConnections forcibly terminates any open keep-alive connections
	// before Close() waits for handlers to finish, eliminating the 5-second
	// "blocked in Close" warning that occurs when a context-canceled request
	// leaves a TCP connection in the active state.
	defer func() {
		srv.CloseClientConnections()
		srv.Close()
	}()

	dc := &DeviceCode{deviceCode: "dc-cancel", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.WaitForToken(ctx, dc)
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
		"expected context cancellation error, got %v", err)
}

func TestWaitForToken_UnknownError(t *testing.T) {
	body, _ := json.Marshal(authErrorResponse{
		Error:            "some_new_error",
		ErrorDescription: "an unexpected condition occurred",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dc := &DeviceCode{deviceCode: "dc-unknown", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.WaitForToken(ctx, dc)
	require.Error(t, err)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr), "expected *APIError, got %T: %v", err, err)
	assert.Equal(t, "some_new_error", apiErr.Code)
	assert.Contains(t, apiErr.Description, "unexpected condition")
}

func TestWaitForToken_MissingAccessToken(t *testing.T) {
	// Server returns HTTP 200 with valid JSON but missing access_token.
	body, _ := json.Marshal(tokenAPIResponse{
		TokenType: "Bearer",
		// AccessToken intentionally absent
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dc := &DeviceCode{deviceCode: "dc-incomplete", interval: 0}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := newTestClient(t, "", "", "", srv.URL, srv.URL)
	_, err := c.WaitForToken(ctx, dc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

// ---------------------------------------------------------------------------
// NewClient — timeout flooring
// ---------------------------------------------------------------------------

func TestNewClient_TimeoutFloor(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "zero timeout is floored to defaultHTTPTimeout",
			timeout: 0,
			want:    defaultHTTPTimeout,
		},
		{
			name:    "5s timeout is floored to defaultHTTPTimeout",
			timeout: 5 * time.Second,
			want:    defaultHTTPTimeout,
		},
		{
			name:    "10s timeout (scan default) is floored to defaultHTTPTimeout",
			timeout: 10 * time.Second,
			want:    defaultHTTPTimeout,
		},
		{
			name:    "30s timeout equals the floor and is unchanged",
			timeout: 30 * time.Second,
			want:    defaultHTTPTimeout,
		},
		{
			name:    "60s timeout is above the floor and is preserved",
			timeout: 60 * time.Second,
			want:    60 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient("", "", "", "", tc.timeout)
			require.NoError(t, err)
			assert.Equal(t, tc.want, c.httpClient.Timeout)
		})
	}
}

// ---------------------------------------------------------------------------
// NewClient — proxy URL validation
// ---------------------------------------------------------------------------

func TestNewClient_Proxy(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantErr  bool
		wantNil  bool
	}{
		{
			name:     "empty proxy uses direct connection",
			proxyURL: "",
			wantErr:  false,
			wantNil:  false,
		},
		{
			name:     "valid socks5 proxy succeeds without dialing",
			proxyURL: "socks5://127.0.0.1:1080",
			wantErr:  false,
			wantNil:  false,
		},
		{
			name:     "malformed URL errors at construction",
			proxyURL: "://bad",
			wantErr:  true,
			wantNil:  true,
		},
		{
			name:     "unsupported scheme errors at construction",
			proxyURL: "ftp://nope",
			wantErr:  true,
			wantNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient("", "", "", tc.proxyURL, 5*time.Second)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// decodeAuthError — table-driven for all 4 sentinel cases plus unknown
// ---------------------------------------------------------------------------

func TestDecodeAuthError_AllStates(t *testing.T) {
	tests := []struct {
		name         string
		errCode      string
		wantSentinel error
		wantAPIErr   bool
	}{
		{
			name:         "authorization_pending maps to ErrAuthorizationPending",
			errCode:      "authorization_pending",
			wantSentinel: ErrAuthorizationPending,
		},
		{
			name:         "slow_down maps to ErrSlowDown",
			errCode:      "slow_down",
			wantSentinel: ErrSlowDown,
		},
		{
			name:         "expired_token maps to ErrExpiredToken",
			errCode:      "expired_token",
			wantSentinel: ErrExpiredToken,
		},
		{
			name:         "access_denied maps to ErrAccessDenied",
			errCode:      "access_denied",
			wantSentinel: ErrAccessDenied,
		},
		{
			name:       "unknown code returns *APIError",
			errCode:    "unsupported_grant_type",
			wantAPIErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(authErrorResponse{
				Error:            tc.errCode,
				ErrorDescription: "test description",
			})

			err := decodeAuthError(http.StatusBadRequest, body)
			require.Error(t, err)

			if tc.wantSentinel != nil {
				assert.True(t, errors.Is(err, tc.wantSentinel),
					"expected errors.Is(%v), got %v", tc.wantSentinel, err)
			}
			if tc.wantAPIErr {
				var apiErr *APIError
				assert.True(t, errors.As(err, &apiErr),
					"expected *APIError, got %T: %v", err, err)
				assert.Equal(t, "unsupported_grant_type", apiErr.Code)
			}
		})
	}
}
