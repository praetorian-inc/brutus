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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
	ms365 "github.com/praetorian-inc/brutus/pkg/enum/microsoft365"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can stub the
// GetCredentialType response without making a real network call. The
// checker's baseURL is irrelevant here — the request never leaves this
// process because the enum HTTP client carried on ctx (see
// enum.WithHTTPClient) is what pkg/enum/microsoft365.CheckAccount uses.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// contextWithCredTypeResponse returns a context carrying an enum HTTP client
// that answers any request with the given GetCredentialType response.
func contextWithCredTypeResponse(t *testing.T, ifExistsResult, throttleStatus int) context.Context {
	t.Helper()
	body, err := json.Marshal(map[string]int{
		"IfExistsResult": ifExistsResult,
		"ThrottleStatus": throttleStatus,
	})
	require.NoError(t, err)

	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	return enum.WithHTTPClient(context.Background(), client)
}

func TestName(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	assert.Equal(t, "microsoft365", p.Name())
}

// TestCheck_MapsIfExistsResultToConfidence verifies the adapter's mapping
// from ms365.Result.IfExistsResult to enum.Result.Confidence — logic that
// lives in this thin adapter, not in the shared pkg/enum/microsoft365
// library (which is covered by its own tests).
func TestCheck_MapsIfExistsResultToConfidence(t *testing.T) {
	tests := []struct {
		name           string
		ifExistsResult int
		wantExists     bool
		wantConfidence enum.Confidence
	}{
		{
			name:           "exists -> high confidence",
			ifExistsResult: ms365.IfExistsResultExists,
			wantExists:     true,
			wantConfidence: enum.ConfidenceHigh,
		},
		{
			name:           "not exists -> high confidence",
			ifExistsResult: ms365.IfExistsResultNotExists,
			wantExists:     false,
			wantConfidence: enum.ConfidenceHigh,
		},
		{
			name:           "different tenant -> exists, high confidence",
			ifExistsResult: ms365.IfExistsResultDifferentTenant,
			wantExists:     true,
			wantConfidence: enum.ConfidenceHigh,
		},
		{
			name:           "domain hint -> exists, high confidence",
			ifExistsResult: ms365.IfExistsResultDomainHint,
			wantExists:     true,
			wantConfidence: enum.ConfidenceHigh,
		},
		{
			name:           "unrecognized code -> low confidence",
			ifExistsResult: 99,
			wantExists:     false,
			wantConfidence: enum.ConfidenceLow,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := contextWithCredTypeResponse(t, tc.ifExistsResult, 0)

			p := &Plugin{}
			result := p.Check(ctx, "user@example.com", 5*time.Second)

			require.NoError(t, result.Error)
			assert.Equal(t, "microsoft365", result.Service)
			assert.Equal(t, "user@example.com", result.Email)
			assert.Equal(t, tc.wantExists, result.Exists)
			assert.Equal(t, tc.wantConfidence, result.Confidence)
		})
	}
}

// TestCheck_PropagatesError verifies that a transport-level error from the
// shared checker is surfaced on enum.Result.Error without a Confidence
// assignment.
func TestCheck_PropagatesError(t *testing.T) {
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
