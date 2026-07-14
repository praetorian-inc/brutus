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

package gravatar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can stub the
// avatar endpoint response without making a real network call. The checker's
// baseURL is irrelevant here — the request never leaves this process because
// the enum HTTP client carried on ctx (see enum.WithHTTPClient) is what
// pkg/enum/gravatar.CheckAccount uses.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// contextWithStatus returns a context carrying an enum HTTP client that
// answers any request with the given status code.
func contextWithStatus(status int) context.Context {
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	return enum.WithHTTPClient(context.Background(), client)
}

func TestName(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	assert.Equal(t, "gravatar", p.Name())
}

// TestCheck verifies the adapter's mapping from gravatar.Result to
// enum.Result — logic that lives in this thin adapter, not in the shared
// pkg/enum/gravatar library (which is covered by its own tests).
func TestCheck(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		wantExists     bool
		wantConfidence enum.Confidence
	}{
		{
			name:           "200 -> exists, high confidence",
			status:         http.StatusOK,
			wantExists:     true,
			wantConfidence: enum.ConfidenceHigh,
		},
		{
			name:           "404 -> not exists, high confidence",
			status:         http.StatusNotFound,
			wantExists:     false,
			wantConfidence: enum.ConfidenceHigh,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := contextWithStatus(tc.status)

			p := &Plugin{}
			result := p.Check(ctx, "user@example.com", 5*time.Second)

			require.NoError(t, result.Error)
			assert.Equal(t, "gravatar", result.Service)
			assert.Equal(t, "user@example.com", result.Email)
			assert.Equal(t, tc.wantExists, result.Exists)
			assert.Equal(t, tc.wantConfidence, result.Confidence)
		})
	}
}

// TestCheck_PropagatesTransportError verifies that a transport/5xx-level
// error from the shared checker is surfaced on enum.Result.Error without a
// Confidence assignment.
func TestCheck_PropagatesTransportError(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}
	ctx := enum.WithHTTPClient(context.Background(), client)

	p := &Plugin{}
	result := p.Check(ctx, "user@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
	assert.Empty(t, result.Confidence)
}

// TestCheck_PropagatesServerError verifies that a non-200/404 status (a
// service error per pkg/enum/gravatar.CheckAccount) is surfaced on
// enum.Result.Error without a Confidence assignment.
func TestCheck_PropagatesServerError(t *testing.T) {
	ctx := contextWithStatus(http.StatusInternalServerError)

	p := &Plugin{}
	result := p.Check(ctx, "user@example.com", 5*time.Second)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
	assert.Empty(t, result.Confidence)
}
