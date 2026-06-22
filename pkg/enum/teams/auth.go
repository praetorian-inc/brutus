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

// Package teams provides a Microsoft Entra ID device code OAuth2 client.
// It starts a device authorization flow, polls for the resulting token set,
// and surfaces typed errors for the terminal authorization states. Token
// values and device codes are never logged (P0-1 security requirement).
package teams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// DefaultClientID is the public Microsoft Teams desktop client ID. It is a
// first-party Microsoft application that supports the device code flow.
const DefaultClientID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

// DefaultScope requests a refresh token plus all statically-configured
// permissions for the Skype/Teams resource.
//
// The "offline_access" portion is required for Azure AD to return a refresh
// token: Azure AD only issues a refresh token when offline_access is requested.
// Without it the raw device-code grant yields no refresh token, so captured
// tokens cannot be renewed AND the enumerator's 401 auto-retry (which depends on
// a refresh token) never fires. offline_access is a reserved OIDC scope and is
// permitted to be combined with a resource ".default" scope.
//
// The "https://api.spaces.skype.com/.default" portion requests every permission
// the app is already statically configured for on the Skype/Teams resource. The
// default Teams desktop client (DefaultClientID) is preauthorized for that
// resource (api.spaces.skype.com), NOT for Microsoft Graph. Requesting a Graph
// scope with this client yields AADSTS65002 (the client is not authorized to
// request a token for that resource), so a Graph default is wrong for the Teams
// enumeration endpoints.
const DefaultScope = "offline_access https://api.spaces.skype.com/.default"

const (
	deviceCodeEndpointFmt       = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	tokenEndpointFmt            = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	deviceCodeGrantType         = "urn:ietf:params:oauth:grant-type:device_code"
	maxResponseBody       int64 = 64 << 10
	minPollInterval             = 5 * time.Second
	maxPollInterval             = 60 * time.Second

	// defaultHTTPTimeout is the minimum per-request timeout for the OAuth
	// endpoints. The device-code flow is interactive and must tolerate slow
	// networks/proxies, so it is NOT governed by the aggressive scan timeout.
	defaultHTTPTimeout = 30 * time.Second
)

// Sentinel errors for use with errors.Is by callers.
var (
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("polling too fast — slow down")
	ErrExpiredToken         = errors.New("device code expired")
	ErrAccessDenied         = errors.New("access denied by user or admin")
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// DeviceCode holds the device authorization response. UserCode and
// VerificationURI are shown to the user; deviceCode and interval are retained
// internally for polling and are never exposed or logged.
type DeviceCode struct {
	UserCode        string
	VerificationURI string
	Message         string
	ExpiresIn       int

	deviceCode string // unexported — used only for polling
	interval   int    // unexported — poll seconds
}

// TokenSet is the OAuth2 token response. Token values must never be logged.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// APIError is returned for unexpected HTTP/OAuth errors from the token or
// device code endpoints.
type APIError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("entra device code error (HTTP %d): %q: %q", e.StatusCode, e.Code, e.Description)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client performs the Microsoft Entra ID device code OAuth2 flow.
type Client struct {
	tenantID   string
	clientID   string
	scopes     string
	httpClient *http.Client

	deviceCodeBaseURL string        // overridable for testing
	tokenBaseURL      string        // overridable for testing
	pollInterval      time.Duration // 0 uses minPollInterval; overridable for testing
}

// NewClient builds a device code client. Empty arguments fall back to the
// organizations tenant, the Microsoft Teams client ID, and the default scopes.
//
// The HTTP client is built via brutus.NewHTTPClientWithProxy, which routes
// requests through the SOCKS5 --proxy when proxyURL is set and still follows
// redirects (unlike enum.NewEnumHTTPClient). Following redirects is required:
// the OAuth2 endpoints redirect and those redirects must be followed.
//
// The HTTP timeout is floored at defaultHTTPTimeout before the client is built
// so interactive auth is not governed by the aggressive per-target scan timeout
// and so the proxy dial timeout is floored too.
func NewClient(tenantID, clientID, scopes, proxyURL string, timeout time.Duration) (*Client, error) {
	if tenantID == "" {
		// Default to the "organizations" endpoint, not "common": the default
		// Teams first-party client is not enabled for consumer (personal MSA)
		// accounts, so /common and /consumers return AADSTS70002 invalid_client.
		tenantID = "organizations"
	}
	if clientID == "" {
		clientID = DefaultClientID
	}
	if scopes == "" {
		scopes = DefaultScope
	}
	if timeout < defaultHTTPTimeout {
		timeout = defaultHTTPTimeout
	}

	httpClient, err := brutus.NewHTTPClientWithProxy(timeout, nil, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("teams: configuring HTTP client: %w", err)
	}

	return &Client{
		tenantID:          tenantID,
		clientID:          clientID,
		scopes:            scopes,
		httpClient:        httpClient,
		deviceCodeBaseURL: fmt.Sprintf(deviceCodeEndpointFmt, tenantID),
		tokenBaseURL:      fmt.Sprintf(tokenEndpointFmt, tenantID),
	}, nil
}

// StartDeviceFlow requests a device code from the authorization endpoint and
// returns the populated DeviceCode. The polling interval is floored at
// minPollInterval seconds.
func (c *Client) StartDeviceFlow(ctx context.Context) (*DeviceCode, error) {
	form := url.Values{
		"client_id": {c.clientID},
		"scope":     {c.scopes},
	}

	resp, err := c.postForm(ctx, c.deviceCodeBaseURL, form)
	if err != nil {
		return nil, fmt.Errorf("starting device flow: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("reading device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, decodeAuthError(resp.StatusCode, body)
	}

	var dcResp deviceCodeAPIResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("decoding device code response: %w", err)
	}

	if dcResp.UserCode == "" || dcResp.VerificationURI == "" || dcResp.DeviceCode == "" {
		return nil, fmt.Errorf("incomplete device code response: missing user_code, verification_uri, or device_code")
	}

	interval := dcResp.Interval
	if interval < int(minPollInterval.Seconds()) {
		interval = int(minPollInterval.Seconds())
	}

	return &DeviceCode{
		UserCode:        dcResp.UserCode,
		VerificationURI: dcResp.VerificationURI,
		Message:         dcResp.Message,
		ExpiresIn:       dcResp.ExpiresIn,
		deviceCode:      dcResp.DeviceCode,
		interval:        interval,
	}, nil
}

// WaitForToken polls the token endpoint until the user completes (or rejects)
// the authorization, the device code expires, or ctx is canceled. It honors
// the standard device-flow polling errors: authorization_pending continues,
// slow_down increases the interval, and expired_token/access_denied terminate
// with the matching sentinel error.
func (c *Client) WaitForToken(ctx context.Context, dc *DeviceCode) (*TokenSet, error) {
	if dc == nil {
		return nil, fmt.Errorf("WaitForToken: DeviceCode must not be nil")
	}
	floor := c.pollInterval
	if floor == 0 {
		floor = minPollInterval
	}
	interval := time.Duration(dc.interval) * time.Second
	if interval < floor {
		interval = floor
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		tok, err := c.poll(ctx, dc.deviceCode)
		switch {
		case err == nil:
			return tok, nil
		case errors.Is(err, ErrAuthorizationPending):
			continue
		case errors.Is(err, ErrSlowDown):
			interval += 5 * time.Second
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
			continue
		default:
			return nil, err
		}
	}
}

// RefreshAccessToken exchanges a refresh token for a new access token via the
// OAuth2 refresh_token grant. It reuses the Client's clientID, token endpoint,
// and scopes. Unlike WaitForToken this is a single request with no polling loop,
// so it always terminates. Token values are never logged (P0-1).
func (c *Client) RefreshAccessToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.clientID},
		"refresh_token": {refreshToken},
		"scope":         {c.scopes},
	}

	resp, err := c.postForm(ctx, c.tokenBaseURL, form)
	if err != nil {
		return nil, fmt.Errorf("refreshing access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, decodeAuthError(resp.StatusCode, body)
	}

	var tokResp tokenAPIResponse
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return nil, fmt.Errorf("decoding refresh response: %w", err)
	}
	if tokResp.AccessToken == "" || tokResp.TokenType == "" {
		return nil, fmt.Errorf("incomplete refresh response: missing access_token or token_type")
	}
	return &TokenSet{
		AccessToken:  tokResp.AccessToken,
		RefreshToken: tokResp.RefreshToken,
		IDToken:      tokResp.IDToken,
		TokenType:    tokResp.TokenType,
		ExpiresIn:    tokResp.ExpiresIn,
		Scope:        tokResp.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second),
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// poll performs a single token endpoint request for the given device code.
// On HTTP 200 it returns a populated TokenSet. On an OAuth error it returns a
// sentinel error (for the recoverable/terminal states) or an *APIError.
func (c *Client) poll(ctx context.Context, deviceCode string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":  {deviceCodeGrantType},
		"client_id":   {c.clientID},
		"device_code": {deviceCode},
	}

	resp, err := c.postForm(ctx, c.tokenBaseURL, form)
	if err != nil {
		return nil, fmt.Errorf("polling for token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tokResp tokenAPIResponse
		if err := json.Unmarshal(body, &tokResp); err != nil {
			return nil, fmt.Errorf("decoding token response: %w", err)
		}
		if tokResp.AccessToken == "" || tokResp.TokenType == "" {
			return nil, fmt.Errorf("incomplete token response: missing access_token or token_type")
		}
		return &TokenSet{
			AccessToken:  tokResp.AccessToken,
			RefreshToken: tokResp.RefreshToken,
			IDToken:      tokResp.IDToken,
			TokenType:    tokResp.TokenType,
			ExpiresIn:    tokResp.ExpiresIn,
			Scope:        tokResp.Scope,
			ExpiresAt:    time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second),
		}, nil
	}

	return nil, decodeAuthError(resp.StatusCode, body)
}

// postForm issues an x-www-form-urlencoded POST request to the given endpoint.
func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.httpClient.Do(req)
}

// decodeAuthError parses an OAuth error envelope and maps known error codes to
// sentinel errors. Unknown codes (and unparseable bodies) become an *APIError.
func decodeAuthError(statusCode int, body []byte) error {
	var errResp authErrorResponse
	_ = json.Unmarshal(body, &errResp)

	switch errResp.Error {
	case "authorization_pending":
		return ErrAuthorizationPending
	case "slow_down":
		return ErrSlowDown
	case "expired_token":
		return ErrExpiredToken
	case "access_denied":
		return ErrAccessDenied
	}

	return &APIError{
		StatusCode:  statusCode,
		Code:        errResp.Error,
		Description: errResp.ErrorDescription,
	}
}

// ---------------------------------------------------------------------------
// JSON-mapping structs (unexported — map exactly to the Entra response shape)
// ---------------------------------------------------------------------------

type deviceCodeAPIResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type tokenAPIResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

type authErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
