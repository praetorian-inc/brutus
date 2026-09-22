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
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func contextWithRoundTrip(rt roundTripFunc) context.Context {
	return enum.WithHTTPClient(context.Background(), &http.Client{Transport: rt})
}

func emptyResponse(req *http.Request, status int, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}
}

func TestCheck_WorkspaceSSO(t *testing.T) {
	t.Parallel()
	ctx := contextWithRoundTrip(func(req *http.Request) (*http.Response, error) {
		h := make(http.Header)
		h.Set("Location", "https://idp.example.com/sso")
		h.Set("Google-Accounts-SAML", "1")
		return emptyResponse(req, http.StatusFound, h), nil
	})

	r := (&Plugin{}).Check(ctx, "user@corp.example", 5*time.Second)
	require.NoError(t, r.Error)
	assert.Equal(t, "google", r.Service)
	assert.True(t, r.Exists)
	assert.Equal(t, enum.ConfidenceHigh, r.Confidence)
}

func TestCheck_GmailGXLU(t *testing.T) {
	t.Parallel()
	ctx := contextWithRoundTrip(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "AccountChooser") {
			h := make(http.Header)
			h.Set("Location", "https://accounts.google.com/ServiceLogin")
			return emptyResponse(req, http.StatusFound, h), nil
		}
		h := make(http.Header)
		h.Add("Set-Cookie", "GMAIL_AT=token; Path=/")
		return emptyResponse(req, http.StatusOK, h), nil
	})

	r := (&Plugin{}).Check(ctx, "user@gmail.com", 5*time.Second)
	require.NoError(t, r.Error)
	assert.True(t, r.Exists)
	assert.Equal(t, enum.ConfidenceHigh, r.Confidence)
}

func TestCheck_DoesNotExist(t *testing.T) {
	t.Parallel()
	ctx := contextWithRoundTrip(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "AccountChooser") {
			h := make(http.Header)
			h.Set("Location", "https://accounts.google.com/ServiceLogin")
			return emptyResponse(req, http.StatusFound, h), nil
		}
		return emptyResponse(req, http.StatusOK, nil), nil
	})

	r := (&Plugin{}).Check(ctx, "nobody@gmail.com", 5*time.Second)
	require.NoError(t, r.Error)
	assert.False(t, r.Exists)
	assert.Equal(t, enum.ConfidenceMedium, r.Confidence)
}

func TestCheck_PropagatesTransportError(t *testing.T) {
	t.Parallel()
	ctx := contextWithRoundTrip(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})

	r := (&Plugin{}).Check(ctx, "user@example.com", 5*time.Second)
	require.Error(t, r.Error)
	assert.False(t, r.Exists)
	assert.Empty(t, r.Confidence)
}
