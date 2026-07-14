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
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can stub the
// avatar endpoint response without a real network call.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// ---------------------------------------------------------------------------
// TestHashEmail
// ---------------------------------------------------------------------------

func TestHashEmail(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "492a8a929d007d94c91cfc1e780aeab3", HashEmail("john.smith@mckesson.com"))
	assert.Equal(t, "a6aaaaf5d124132f358752c7d72d4b44", HashEmail("noreply@example.com"))

	// Mixed case and surrounding whitespace must normalize to the same hash.
	assert.Equal(t, HashEmail("john.smith@mckesson.com"), HashEmail("  John.Smith@McKesson.com  "))
}

// ---------------------------------------------------------------------------
// TestCheckAccount — mock server keyed by hash, mirroring microsoft365's
// newMockServer pattern.
// ---------------------------------------------------------------------------

// registeredEmail is the email whose Gravatar hash the mock server treats as
// "registered" (200); every other hash 404s.
const registeredEmail = "exists@example.com"

func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	registeredHash := HashEmail(registeredEmail)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPrefix := "/avatar/"
		if !strings.HasPrefix(r.URL.Path, wantPrefix) {
			http.NotFound(w, r)
			return
		}
		hash := strings.TrimPrefix(r.URL.Path, wantPrefix)

		assert.Equal(t, "404", r.URL.Query().Get("d"), "gravatar request must set d=404")

		if hash == registeredHash {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestCheckAccount_Exists(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), registeredEmail)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, registeredEmail, result.Email)
	assert.Equal(t, HashEmail(registeredEmail), result.Hash)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestCheckAccount_NotExists(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "notexists@example.com")

	require.NoError(t, result.Error)
	assert.False(t, result.Exists)
	assert.Equal(t, "notexists@example.com", result.Email)
	assert.Equal(t, HashEmail("notexists@example.com"), result.Hash)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestCheckAccount_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "test@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected status")
	assert.False(t, result.Exists)
	assert.Equal(t, "test@example.com", result.Email)
	assert.Equal(t, HashEmail("test@example.com"), result.Hash)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestCheckAccount_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(ctx, registeredEmail)

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
}

// ---------------------------------------------------------------------------
// TestNewChecker — default baseURL is asserted indirectly by pointing the
// checker at a test server and verifying it can be constructed with an empty
// baseURL/proxyURL without error (baseURL is unexported, so behavior is
// verified via CheckAccount against a real server rather than field access).
// ---------------------------------------------------------------------------

func TestNewChecker_DefaultBaseURLUsedWhenEmpty(t *testing.T) {
	t.Parallel()
	c, err := NewChecker("", "", 5*time.Second)
	require.NoError(t, err)
	require.NotNil(t, c)

	// Exercise CheckAccount against the real default endpoint's context-carried
	// client stub to confirm the checker is usable without hitting the network:
	// injecting a context client proves NewChecker("", ...) produced a working
	// Checker whose CheckAccount constructs a valid request against
	// DefaultBaseURL (the request must at least be well-formed; a malformed
	// baseURL would fail request construction).
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.True(t, strings.HasPrefix(req.URL.String(), DefaultBaseURL+"/avatar/"),
				"request URL must be built from DefaultBaseURL when baseURL is empty")
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	ctx := enum.WithHTTPClient(context.Background(), client)
	result := c.CheckAccount(ctx, "someone@example.com")
	require.NoError(t, result.Error)
	assert.False(t, result.Exists)
}

func TestNewChecker_WithProxyURL(t *testing.T) {
	t.Parallel()
	c, err := NewChecker("", "http://user:pass@127.0.0.1:1/", 5*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

// ---------------------------------------------------------------------------
// enum.HTTPClientFromContext precedence: CheckAccount must prefer a shared
// enum HTTP client carried on ctx (set via enum.WithHTTPClient) over the
// Checker's own client, and fall back to its own client when ctx carries
// none.
// ---------------------------------------------------------------------------

func TestCheckAccount_UsesHTTPClientFromContext(t *testing.T) {
	t.Parallel()

	// baseURL points at a server that always 500s. If the request reaches this
	// server, the test fails via "unexpected status" — proving the
	// context-carried client (which never dials this server at all) was used
	// instead.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)

	c, err := NewChecker(failing.URL, "", 5*time.Second)
	require.NoError(t, err)

	contextClient := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	ctx := enum.WithHTTPClient(context.Background(), contextClient)

	result := c.CheckAccount(ctx, registeredEmail)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "the context-carried client's response must be used, not the failing server's")
}

func TestCheckAccount_FallsBackToOwnClientWithoutContextClient(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	// No enum.WithHTTPClient on this context — CheckAccount must fall back to
	// the Checker's own client and still reach srv successfully.
	result := c.CheckAccount(context.Background(), registeredEmail)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_Callback
// 4 emails, threads=4, onResult callback appends under a mutex.
// After the run:
//   - callback invoked exactly once per email
//   - returned slice len == 4
//   - set of emails from callback matches input set
//   - results are in input order
//
// Run the package under -race (go test -race ./pkg/enum/gravatar/) to verify
// the callback serialization guarantee.
// ---------------------------------------------------------------------------

func TestEnumerateWith_Callback(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{
		registeredEmail,
		"notexists@example.com",
		"another@example.com",
		"nobody@example.com",
	}

	var mu sync.Mutex
	var callbackResults []Result

	results := c.EnumerateWith(
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
	require.Len(t, results, len(emails), "EnumerateWith must return one Result per email")

	// Callback must be invoked exactly once per email.
	assert.Len(t, callbackResults, len(emails), "onResult callback must be invoked exactly once per email")

	// The set of emails seen by the callback must equal the input set.
	cbEmails := make(map[string]struct{}, len(callbackResults))
	for _, r := range callbackResults {
		cbEmails[r.Email] = struct{}{}
	}
	for _, email := range emails {
		assert.Contains(t, cbEmails, email, "onResult callback must have been called for email %q", email)
	}

	// Returned results must preserve input order.
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email, "results[%d] must correspond to emails[%d]", i, i)
	}

	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	existsResult := byEmail[registeredEmail]
	assert.NoError(t, existsResult.Error)
	assert.True(t, existsResult.Exists)

	for _, email := range []string{"notexists@example.com", "another@example.com", "nobody@example.com"} {
		r := byEmail[email]
		assert.NoError(t, r.Error, "email %q must not have an error", email)
		assert.False(t, r.Exists, "email %q must be Exists=false", email)
	}
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_NilCallback
// Passing nil as the callback must not panic and must return one result per
// email.
// ---------------------------------------------------------------------------

func TestEnumerateWith_NilCallback(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{registeredEmail, "notexists@example.com"}

	results := c.EnumerateWith(context.Background(), emails, 2, 0, 0, nil)
	require.Len(t, results, len(emails), "nil callback must not panic; must return one result per email")
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_CanceledContextRecordsAllSlots
// Regression guard: with an already-canceled context, every worker hits the
// <-ctx.Done() guard before the HTTP call. Each guard must still record
// before returning, so every index is filled (Email set, input order
// preserved) and the callback fires exactly once per email.
// ---------------------------------------------------------------------------

func TestEnumerateWith_CanceledContextRecordsAllSlots(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{registeredEmail, "notexists@example.com", "nobody@example.com"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var mu sync.Mutex
	var cbResults []Result

	results := c.EnumerateWith(ctx, emails, 4, 0, 0, func(r Result) {
		mu.Lock()
		cbResults = append(cbResults, r)
		mu.Unlock()
	})

	require.Len(t, results, len(emails), "every slot must be filled even when ctx is already canceled")

	for i := range emails {
		assert.Equal(t, emails[i], results[i].Email,
			"results[%d].Email must be set (input order preserved), not left as a dropped zero-value", i)
		assert.Error(t, results[i].Error, "results[%d] must carry the ctx.Done() error, not be silently dropped", i)
		assert.True(t, errors.Is(results[i].Error, context.Canceled),
			"results[%d].Error must be context.Canceled from the <-ctx.Done() guard", i)
	}

	assert.Len(t, cbResults, len(emails), "onResult callback must fire exactly once per email, even on the canceled-context path")
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_ZeroOrNegativeThreadsDoesNotHang
// Regression guard: threads<=0 must be normalized to 1 before g.SetLimit.
// SetLimit(0) would permit zero concurrent goroutines, so no worker could
// ever run and EnumerateWith would hang forever.
// ---------------------------------------------------------------------------

func TestEnumerateWith_ZeroOrNegativeThreadsDoesNotHang(t *testing.T) {
	tests := []struct {
		name    string
		threads int
	}{
		{"zero", 0},
		{"negative", -1},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newMockServer(t)
			t.Cleanup(srv.Close)

			c, err := NewChecker(srv.URL, "", 5*time.Second)
			require.NoError(t, err)

			emails := []string{registeredEmail, "notexists@example.com"}

			done := make(chan []Result, 1)
			go func() {
				done <- c.EnumerateWith(context.Background(), emails, tc.threads, 0, 0, nil)
			}()

			select {
			case results := <-done:
				require.Len(t, results, len(emails), "threads=%d must still return one result per email", tc.threads)
				for i := range emails {
					assert.Equal(t, emails[i], results[i].Email,
						"results[%d] must preserve input order under normalized serial execution", i)
					assert.NoError(t, results[i].Error, "results[%d] must succeed against the mock server", i)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("EnumerateWith hung with threads=%d", tc.threads)
			}
		})
	}
}
