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

package google

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockGoogleServer creates an httptest.Server that simulates Google's
// AccountChooser and GXLU endpoints. The email query parameter drives
// which response is returned.
func newMockGoogleServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// AccountChooser endpoint
	mux.HandleFunc("/AccountChooser", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("Email")
		switch email {
		case "saml@example.com":
			// Valid SSO account — returns SAML header
			w.Header().Set("Google-Accounts-SAML", "true")
			w.WriteHeader(http.StatusFound)
		case "redirect@example.com":
			// Valid account — redirects to non-Google IdP
			w.Header().Set("Location", "https://idp.example.com/sso/saml")
			w.WriteHeader(http.StatusFound)
		default:
			// Unknown account — redirects back to Google login
			w.Header().Set("Location", "https://accounts.google.com/ServiceLogin")
			w.WriteHeader(http.StatusFound)
		}
	})

	// GXLU endpoint
	mux.HandleFunc("/mail/gxlu", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		switch email {
		case "gmail@example.com":
			// Gmail-enabled account — returns GMAIL_AT cookie
			http.SetCookie(w, &http.Cookie{Name: "GMAIL_AT", Value: "token123"})
			w.WriteHeader(http.StatusOK)
		default:
			// No Gmail account
			w.WriteHeader(http.StatusOK)
		}
	})

	return httptest.NewServer(mux)
}

func TestCheck_AccountChooserSAML(t *testing.T) {
	t.Parallel()
	srv := newMockGoogleServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(context.Background(), "saml@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "SAML header should indicate account exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
	assert.Equal(t, "google", result.Service)
	assert.Equal(t, "saml@example.com", result.Email)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCheck_AccountChooserRedirect(t *testing.T) {
	t.Parallel()
	srv := newMockGoogleServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(context.Background(), "redirect@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "non-Google redirect should indicate account exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

func TestCheck_GXLUCookie(t *testing.T) {
	t.Parallel()
	srv := newMockGoogleServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(context.Background(), "gmail@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "GMAIL_AT cookie should indicate account exists")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

func TestCheck_NotFound(t *testing.T) {
	t.Parallel()
	srv := newMockGoogleServer(t)
	t.Cleanup(srv.Close)

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(context.Background(), "unknown@example.com", 5*time.Second)

	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "unknown email should not exist")
	assert.Equal(t, enum.ConfidenceMedium, result.Confidence)
}

func TestCheck_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(context.Background(), "test@example.com", 5*time.Second)

	// Server errors don't set result.Error (the check functions return false, nil
	// for non-matching responses). The result should be Exists=false.
	assert.False(t, result.Exists)
	assert.Equal(t, enum.ConfidenceMedium, result.Confidence)
}

func TestCheck_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockGoogleServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &Plugin{accountChooserBaseURL: srv.URL, gxluBaseURL: srv.URL}
	result := p.Check(ctx, "saml@example.com", 5*time.Second)

	// With cancelled context, HTTP requests fail. The check functions return
	// errors but Check() treats errors as "not confirmed" and falls through.
	assert.False(t, result.Exists)
}

func TestName(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	assert.Equal(t, "google", p.Name())
}
