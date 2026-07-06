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

// White-box tests for pkg/enum/google. Being in the same package lets us set
// the unexported accountChooserBaseURL and gxluBaseURL fields on the Enumerator
// to httptest server URLs, exactly mirroring the teams Enumerator test pattern.
package google

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestEnumerator builds an Enumerator with base URLs pointing at the
// provided httptest servers. Either server may be nil, in which case that
// field is left pointing at the real default (safe for tests that only
// exercise one of the two oracles through a mock server while the other
// oracle produces a "not found" response from the mock as well).
func newTestEnumerator(t *testing.T, srv *httptest.Server) *Enumerator {
	t.Helper()
	e, err := NewEnumerator("", 5*time.Second)
	require.NoError(t, err, "NewEnumerator must succeed")
	if srv != nil {
		e.accountChooserBaseURL = srv.URL
		e.gxluBaseURL = srv.URL
	}
	return e
}

// newMockServer creates an httptest.Server that simulates both the
// AccountChooser and GXLU endpoints. The email parameter drives which
// response is returned, mirroring the routing logic described in the package
// doc and google.go.
//
// Routing:
//
//	/AccountChooser?Email=saml@...      → Google-Accounts-SAML header (no Location)
//	/AccountChooser?Email=okta@...      → Location: https://login.okta.com/... (non-Google)
//	/AccountChooser?Email=*             → Location: https://accounts.google.com/ServiceLogin (not found)
//	/mail/gxlu?email=gmail@...          → Set-Cookie: GMAIL_AT=tok
//	/mail/gxlu?email=*                  → 200, no cookie
func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/AccountChooser", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("Email")
		switch email {
		case "saml@example.com":
			// SAML header only (no Location) — valid SSO account on a headeronly domain.
			w.Header().Set("Google-Accounts-SAML", "v1")
			w.WriteHeader(http.StatusOK)
		case "okta@example.com":
			// Non-Google redirect Location — SSO redirect to an external IdP.
			w.Header().Set("Location", "https://login.okta.com/sso/saml2?iss=foo")
			w.WriteHeader(http.StatusFound)
		case "gmail@example.com":
			// Falls through to Google login (no SSO) — not found via AccountChooser.
			w.Header().Set("Location", "https://accounts.google.com/ServiceLogin")
			w.WriteHeader(http.StatusFound)
		default:
			// Unknown account — redirects back to Google login.
			w.Header().Set("Location", "https://accounts.google.com/ServiceLogin")
			w.WriteHeader(http.StatusFound)
		}
	})

	mux.HandleFunc("/mail/gxlu", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "gmail@example.com" {
			http.SetCookie(w, &http.Cookie{Name: "GMAIL_AT", Value: "tok123"})
		}
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// TestCheckAccount_WorkspaceSSO_SAMLHeader
// AccountChooser responds with Google-Accounts-SAML header and no Location.
// Existence confirmed, Method=workspace-sso, IdP="" (no Location to parse).
// ---------------------------------------------------------------------------

func TestCheckAccount_WorkspaceSSO_SAMLHeader(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)
	res := e.CheckAccount(context.Background(), "saml@example.com")

	require.NoError(t, res.Error)
	assert.True(t, res.Exists, "SAML header must confirm account exists")
	assert.Equal(t, MethodWorkspaceSSO, res.Method)
	// No Location header was set, so IdP must be empty.
	assert.Empty(t, res.IdP, "IdP must be empty when only the SAML header is present (no Location)")
	assert.Equal(t, "saml@example.com", res.Email)
}

// ---------------------------------------------------------------------------
// TestCheckAccount_WorkspaceSSO_NonGoogleRedirect
// AccountChooser returns Location to a non-Google host (Okta IdP redirect).
// Existence confirmed, Method=workspace-sso, IdP="login.okta.com".
// ---------------------------------------------------------------------------

func TestCheckAccount_WorkspaceSSO_NonGoogleRedirect(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)
	res := e.CheckAccount(context.Background(), "okta@example.com")

	require.NoError(t, res.Error)
	assert.True(t, res.Exists, "non-Google Location redirect must confirm account exists")
	assert.Equal(t, MethodWorkspaceSSO, res.Method)
	assert.Equal(t, "login.okta.com", res.IdP,
		"IdP must be the host parsed from the non-Google redirect Location")
	assert.Equal(t, "okta@example.com", res.Email)
}

// ---------------------------------------------------------------------------
// TestCheckAccount_Gmail_GXLU
// AccountChooser returns Google ServiceLogin (not found via SSO).
// GXLU server sets GMAIL_AT cookie → Exists=true, Method=gmail, IdP="".
// ---------------------------------------------------------------------------

func TestCheckAccount_Gmail_GXLU(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)
	res := e.CheckAccount(context.Background(), "gmail@example.com")

	require.NoError(t, res.Error)
	assert.True(t, res.Exists, "GMAIL_AT cookie must confirm account exists")
	assert.Equal(t, MethodGmail, res.Method)
	assert.Empty(t, res.IdP, "IdP must be empty for gmail method")
	assert.Equal(t, "gmail@example.com", res.Email)
}

// ---------------------------------------------------------------------------
// TestCheckAccount_NotFound
// AccountChooser: Google ServiceLogin redirect (no SSO).
// GXLU: no GMAIL_AT cookie.
// Result: Exists=false, Method=MethodNone.
// ---------------------------------------------------------------------------

func TestCheckAccount_NotFound(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv)
	res := e.CheckAccount(context.Background(), "unknown@example.com")

	require.NoError(t, res.Error)
	assert.False(t, res.Exists, "account not confirmed by any oracle must be Exists=false")
	assert.Equal(t, MethodNone, res.Method)
	assert.Empty(t, res.IdP)
	assert.Equal(t, "unknown@example.com", res.Email)
}

// ---------------------------------------------------------------------------
// TestCheckAccount_TransportError (optional)
// Point base URLs at a closed port → transport error → Exists=false, Error!=nil.
// ---------------------------------------------------------------------------

func TestCheckAccount_TransportError(t *testing.T) {
	t.Parallel()

	// Bind and immediately close a listener to get a port that will refuse
	// connections — avoids an unpredictable timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := "http://" + ln.Addr().String()
	_ = ln.Close()

	e, err := NewEnumerator("", 2*time.Second)
	require.NoError(t, err)
	e.accountChooserBaseURL = closedAddr
	e.gxluBaseURL = closedAddr

	res := e.CheckAccount(context.Background(), "any@example.com")

	assert.False(t, res.Exists, "transport error must yield Exists=false")
	assert.NotNil(t, res.Error, "transport error must be reflected in Result.Error")
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_Callback
// 6 emails, threads=4, onResult callback appends under a mutex.
// After the run:
//   - callback invoked exactly once per email
//   - returned slice len == 6
//   - set of emails from callback matches input set
//   - results are in input order
//
// Run the package under -race (go test -race ./pkg/enum/google/) to verify
// the callback serialization guarantee.
// ---------------------------------------------------------------------------

func TestEnumerateWith_Callback(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	emails := []string{
		"saml@example.com",
		"okta@example.com",
		"gmail@example.com",
		"unknown@example.com",
		"other1@example.com",
		"other2@example.com",
	}

	e := newTestEnumerator(t, srv)

	var mu sync.Mutex
	var callbackResults []Result

	results := e.EnumerateWith(
		context.Background(),
		emails,
		4, // threads
		0, // rateLimit (no throttle)
		0, // jitter
		func(r Result) {
			mu.Lock()
			callbackResults = append(callbackResults, r)
			mu.Unlock()
		},
	)

	// Returned slice must have exactly one entry per input email.
	require.Len(t, results, len(emails),
		"EnumerateWith must return one Result per email")

	// Callback must be invoked exactly once per email.
	assert.Len(t, callbackResults, len(emails),
		"onResult callback must be invoked exactly once per email")

	// The set of emails seen by the callback must equal the input set.
	cbEmails := make(map[string]struct{}, len(callbackResults))
	for _, r := range callbackResults {
		cbEmails[r.Email] = struct{}{}
	}
	for _, e := range emails {
		assert.Contains(t, cbEmails, e,
			"onResult callback must have been called for email %q", e)
	}

	// Returned results must preserve input order.
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email,
			"results[%d] must correspond to emails[%d]", i, i)
	}
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_NilCallback
// Passing nil as the callback must not panic and must return one result per email.
// ---------------------------------------------------------------------------

func TestEnumerateWith_NilCallback(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	emails := []string{"a@example.com", "b@example.com", "c@example.com"}
	e := newTestEnumerator(t, srv)

	results := e.EnumerateWith(context.Background(), emails, 2, 0, 0, nil)
	require.Len(t, results, len(emails), "nil callback must not panic; must return one result per email")
}

// ---------------------------------------------------------------------------
// idpHost helper (unit coverage for the unexported helper)
// ---------------------------------------------------------------------------

func Test_idpHost(t *testing.T) {
	tests := []struct {
		location string
		want     string
	}{
		{"https://login.okta.com/sso/saml2", "login.okta.com"},
		{"https://adfs.contoso.com/adfs/ls/", "adfs.contoso.com"},
		{"", ""},
		{"not-a-url::garbage", ""},
		{"https://accounts.google.com/ServiceLogin", "accounts.google.com"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.location, func(t *testing.T) {
			t.Parallel()
			got := idpHost(tc.location)
			assert.Equal(t, tc.want, got)
		})
	}
}
