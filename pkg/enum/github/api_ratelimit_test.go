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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAPIRateLimited(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		want   bool
	}{
		{name: "429", status: http.StatusTooManyRequests, want: true},
		{
			name:   "403 with Retry-After",
			status: http.StatusForbidden,
			header: http.Header{"Retry-After": []string{"5"}},
			want:   true,
		},
		{
			name:   "403 secondary rate limit message",
			status: http.StatusForbidden,
			body:   `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`,
			want:   true,
		},
		{
			name:   "403 abuse detection message",
			status: http.StatusForbidden,
			body:   `{"message":"You have triggered an abuse detection mechanism"}`,
			want:   true,
		},
		{
			name:   "403 forbidden",
			status: http.StatusForbidden,
			body:   `{"message":"Resource not accessible by integration"}`,
			want:   false,
		},
		{name: "404", status: http.StatusNotFound, want: false},
		{name: "200", status: http.StatusOK, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     tt.header,
				Body:       io.NopCloser(strings.NewReader(tt.body)),
			}
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			assert.Equal(t, tt.want, isAPIRateLimited(resp))
		})
	}
}

func TestRateLimitWait_RetryAfterAndBackoff(t *testing.T) {
	t.Parallel()

	withRetryAfter := &http.Response{Header: http.Header{"Retry-After": []string{"7"}}}
	d, ok := parseRetryAfter(withRetryAfter)
	require.True(t, ok)
	assert.Equal(t, 7*time.Second, d)
	assert.Equal(t, 7*time.Second, rateLimitWait(withRetryAfter, 0))

	noHeader := &http.Response{Header: make(http.Header)}
	assert.Equal(t, rateLimitBackoff, rateLimitWait(noHeader, 0))
	assert.Equal(t, 2*rateLimitBackoff, rateLimitWait(noHeader, 1))
	assert.Equal(t, 4*rateLimitBackoff, rateLimitWait(noHeader, 2))
	assert.Equal(t, apiRateLimitBackoffCap, rateLimitWait(noHeader, 30))
}

func TestAPIRequest_429ThenSucceed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestAPIRequest_403SecondaryRetryAfterThenSucceed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	var slept []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "9")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	e.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}

	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
	require.Equal(t, []time.Duration{9 * time.Second}, slept)
}

func TestAPIRequest_403AbuseBodyThenSucceed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"You have triggered an abuse detection mechanism"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), calls.Load())
}

func TestAPIRequest_403ForbiddenNotRetried(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int32(1), calls.Load(), "a non-rate-limit 403 must not be retried")
}

func TestAPIRequest_RetriesExhausted(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, int32(apiRateLimitRetries+1), calls.Load())
}

func TestAPIRequest_ExponentialBackoffWithoutRetryAfter(t *testing.T) {
	t.Parallel()

	var slept []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	e.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}

	resp, err := e.apiRequest(context.Background(), http.MethodGet, "/user", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	require.Len(t, slept, apiRateLimitRetries)
	for i, d := range slept {
		assert.Equal(t, rateLimitWait(&http.Response{Header: make(http.Header)}, i), d)
	}
}

func TestAPIRequest_CancelDuringBackoff(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.sleep = func(_ context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}

	resp, err := e.apiRequest(ctx, http.MethodGet, "/user", nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestListCommitLogins_429ThenSucceed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, renderCommits([]fakeCommit{
			{email: "alice@example.com", login: "alice-gh"},
		}))
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	mapping, err := e.listCommitLogins(context.Background(), "owner", "repo", "main", []string{"alice@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "alice-gh", mapping["alice@example.com"])
	assert.Equal(t, int32(2), calls.Load())
}

func TestListCommitLogins_403SecondaryThenSucceed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, renderCommits([]fakeCommit{
			{email: "alice@example.com", login: "alice-gh"},
		}))
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	mapping, err := e.listCommitLogins(context.Background(), "owner", "repo", "main", []string{"alice@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "alice-gh", mapping["alice@example.com"])
	assert.Equal(t, int32(2), calls.Load())
}

func TestListCommitLogins_403ForbiddenStillFatal(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, nil, srv, "tok")
	_, err := e.listCommitLogins(context.Background(), "owner", "repo", "main", []string{"alice@example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Equal(t, int32(1), calls.Load())
}
