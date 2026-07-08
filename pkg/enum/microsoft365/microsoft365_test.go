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
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// roundTripFunc adapts a function to http.RoundTripper so tests can stub the
// GetCredentialType response without a real network call.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/common/GetCredentialType" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req2 credTypeRequest
		if err := json.Unmarshal(body, &req2); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var resp credTypeResponse
		switch req2.Username {
		case "exists@example.com":
			resp = credTypeResponse{IfExistsResult: 0}
		case "notexists@example.com":
			resp = credTypeResponse{IfExistsResult: 1}
		case "difftenant@example.com":
			resp = credTypeResponse{IfExistsResult: 5}
		case "domainhint@example.com":
			resp = credTypeResponse{IfExistsResult: 6}
		case "unknown@example.com":
			resp = credTypeResponse{IfExistsResult: 99}
		case "throttled@example.com":
			resp = credTypeResponse{IfExistsResult: 0, ThrottleStatus: 1}
		case "federated@example.com":
			resp = credTypeResponse{
				IfExistsResult:        0,
				FederationRedirectUrl: "https://adfs.example.com/adfs/ls/",
			}
		default:
			resp = credTypeResponse{IfExistsResult: 1}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestCheckAccount_Exists(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "exists@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultExists, result.IfExistsResult)
	assert.False(t, result.Federated)
	assert.Greater(t, result.Duration, time.Duration(0))
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
	assert.Equal(t, IfExistsResultNotExists, result.IfExistsResult)
}

func TestCheckAccount_DifferentTenant(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "difftenant@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultDifferentTenant, result.IfExistsResult)
}

func TestCheckAccount_DomainHint(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "domainhint@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, IfExistsResultDomainHint, result.IfExistsResult)
}

func TestCheckAccount_UnknownResult(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "unknown@example.com")

	require.NoError(t, result.Error)
	assert.False(t, result.Exists)
	assert.Equal(t, 99, result.IfExistsResult)
}

func TestCheckAccount_Throttled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "throttled@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "throttled")
	assert.False(t, result.Exists)
}

func TestCheckAccount_Federated(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "federated@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
	assert.True(t, result.Federated)
	assert.Equal(t, "https://adfs.example.com/adfs/ls/", result.FederationURL)
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
}

func TestCheckAccount_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(context.Background(), "test@example.com")

	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "decoding response")
}

func TestCheckAccount_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)
	result := c.CheckAccount(ctx, "exists@example.com")

	require.Error(t, result.Error)
	assert.False(t, result.Exists)
}

func TestNewChecker_DefaultBaseURL(t *testing.T) {
	t.Parallel()
	c, err := NewChecker("", "", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, DefaultBaseURL, c.baseURL)
}

func TestNewChecker_WithProxyURL(t *testing.T) {
	t.Parallel()
	c, err := NewChecker("", "http://user:pass@127.0.0.1:1/", 5*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, c)
}

// ---------------------------------------------------------------------------
// enum.HTTPClientFromContext proxy support (dev): CheckAccount must prefer a
// shared enum HTTP client carried on ctx (set for a run via
// enum.WithHTTPClient to honor --proxy and connection pooling) over the
// Checker's own client, and fall back to its own client when ctx carries
// none.
// ---------------------------------------------------------------------------

func TestCheckAccount_UsesHTTPClientFromContext(t *testing.T) {
	t.Parallel()

	// baseURL points at a server that always 500s. If the request reaches
	// this server, the test fails via "unexpected status" — proving the
	// context-carried client (which never dials this server at all) was
	// used instead.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)

	c, err := NewChecker(failing.URL, "", 5*time.Second)
	require.NoError(t, err)

	body, err := json.Marshal(credTypeResponse{IfExistsResult: IfExistsResultExists})
	require.NoError(t, err)
	contextClient := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	ctx := enum.WithHTTPClient(context.Background(), contextClient)

	result := c.CheckAccount(ctx, "exists@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "the context-carried client's response must be used, not the failing server's")
	assert.Equal(t, IfExistsResultExists, result.IfExistsResult)
}

func TestCheckAccount_FallsBackToOwnClientWithoutContextClient(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	// No enum.WithHTTPClient on this context — CheckAccount must fall back
	// to the Checker's own client and still reach srv successfully.
	result := c.CheckAccount(context.Background(), "exists@example.com")

	require.NoError(t, result.Error)
	assert.True(t, result.Exists)
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
// Run the package under -race (go test -race ./pkg/enum/microsoft365/) to
// verify the callback serialization guarantee.
// ---------------------------------------------------------------------------

func TestEnumerateWith_Callback(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{
		"exists@example.com",
		"notexists@example.com",
		"difftenant@example.com",
		"domainhint@example.com",
		"federated@example.com",
		"unknown@example.com",
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
	for _, email := range emails {
		assert.Contains(t, cbEmails, email,
			"onResult callback must have been called for email %q", email)
	}

	// Returned results must preserve input order.
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email,
			"results[%d] must correspond to emails[%d]", i, i)
	}

	// Spot-check known-exists emails.
	byEmail := make(map[string]Result, len(results))
	for _, r := range results {
		byEmail[r.Email] = r
	}

	for _, email := range []string{"exists@example.com", "difftenant@example.com", "domainhint@example.com", "federated@example.com"} {
		r := byEmail[email]
		assert.NoError(t, r.Error, "email %q must not have an error", email)
		assert.True(t, r.Exists, "email %q must be Exists=true", email)
	}

	for _, email := range []string{"notexists@example.com", "unknown@example.com"} {
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

	emails := []string{"exists@example.com", "notexists@example.com", "unknown@example.com"}

	results := c.EnumerateWith(context.Background(), emails, 2, 0, 0, nil)
	require.Len(t, results, len(emails), "nil callback must not panic; must return one result per email")
}

// ---------------------------------------------------------------------------
// TestEnumerateWith_CanceledContextRecordsAllSlots
// Regression guard: with an already-canceled context, every worker hits the
// <-ctx.Done() guard before the HTTP call. Each guard must still call
// record(i, ...) before returning, so every index is filled (Email set, input
// order preserved) and the callback fires exactly once per email. Reverting
// that record() call leaves the dropped slots as zero-value Result{} (empty
// Email, nil Error) and skips the callback for those emails.
// ---------------------------------------------------------------------------

func TestEnumerateWith_CanceledContextRecordsAllSlots(t *testing.T) {
	t.Parallel()

	srv := newMockServer(t)
	t.Cleanup(srv.Close)

	c, err := NewChecker(srv.URL, "", 5*time.Second)
	require.NoError(t, err)

	emails := []string{"exists@example.com", "notexists@example.com", "unknown@example.com"}

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
// SetLimit(0) would permit zero concurrent goroutines, so no worker could ever
// run and EnumerateWith would hang forever. Guarded by a timeout rather than
// relying solely on `go test -timeout`, so failure is immediate and specific.
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

			emails := []string{"exists@example.com", "notexists@example.com"}

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
