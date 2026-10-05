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

package github

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

const joinHTML = `<!DOCTYPE html><html><body><auto-check src="/email_validity_checks"><input type="hidden" value="csrf-token"></auto-check></body></html>`

func httpresp(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    req,
	}
}

func githubRoundTrip(existsEmail string) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/join"):
			return httpresp(req, http.StatusOK, joinHTML), nil
		case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "email_validity_checks"):
			raw, _ := io.ReadAll(req.Body)
			vals, _ := url.ParseQuery(string(raw))
			email := vals.Get("value")
			if strings.Contains(email, "@foobar.com") {
				return httpresp(req, http.StatusOK, ""), nil
			}
			if email == existsEmail {
				return httpresp(req, http.StatusUnprocessableEntity, ""), nil
			}
			return httpresp(req, http.StatusOK, ""), nil
		default:
			return httpresp(req, http.StatusNotFound, ""), nil
		}
	}
}

func TestCheck_Exists(t *testing.T) {
	t.Parallel()
	ctx := enum.WithHTTPClient(context.Background(), &http.Client{Transport: githubRoundTrip("taken@example.com")})
	r := (&Plugin{}).Check(ctx, "taken@example.com", 5*time.Second)
	require.NoError(t, r.Error)
	assert.Equal(t, "github", r.Service)
	assert.True(t, r.Exists)
	assert.Equal(t, enum.ConfidenceHigh, r.Confidence)
}

func TestCheck_Available(t *testing.T) {
	t.Parallel()
	ctx := enum.WithHTTPClient(context.Background(), &http.Client{Transport: githubRoundTrip("taken@example.com")})
	r := (&Plugin{}).Check(ctx, "fresh@example.com", 5*time.Second)
	require.NoError(t, r.Error)
	assert.False(t, r.Exists)
	assert.Equal(t, enum.ConfidenceHigh, r.Confidence)
}

func TestCheck_PropagatesTransportError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(enum.WithHTTPClient(context.Background(), &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}), 300*time.Millisecond)
	defer cancel()
	r := (&Plugin{}).Check(ctx, "user@example.com", 5*time.Second)
	require.Error(t, r.Error)
	assert.False(t, r.Exists)
	assert.Equal(t, enum.ConfidenceMedium, r.Confidence)
}
