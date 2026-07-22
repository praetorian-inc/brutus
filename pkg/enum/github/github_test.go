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

// White-box tests for pkg/enum/github. Being in the same package lets us set
// the unexported webBaseURL, apiBaseURL, settleDelay, sleep, and newName
// fields on the Enumerator directly — the same pattern as pkg/enum/google.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test infrastructure helpers
// ---------------------------------------------------------------------------

// noopSleep is a sleep function that returns immediately without sleeping.
// It is used to replace the real sleepCtx in tests so rate-limit retries don't
// cause real delays.
func noopSleep(_ context.Context, _ time.Duration) error { return nil }

// deterministicName returns a predictable name for use in Reveal flow tests,
// where the same name is returned every call. Tests that need unique names per
// call should use a counter-based newName.
func deterministicName() string { return "test-repo-name" }

// webMux builds an http.ServeMux that fakes the GitHub web flow. The statusFor
// map controls which HTTP status the /email_validity_checks POST returns per
// email value (default 200 = available).
//
// It serves:
//
//	GET  /join                        — returns an HTML page with the CSRF token
//	POST /email_validity_checks       — returns statusFor[email] (or 200)
func webMux(t *testing.T, csrfToken string, statusFor map[string]int) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	// /join returns a minimal HTML page with the auto-check block.
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)
	})

	// /email_validity_checks returns the configured status per email.
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		email := r.FormValue("value")
		status, ok := statusFor[email]
		if !ok {
			status = http.StatusOK // default: available
		}
		w.WriteHeader(status)
	})

	return mux
}

// newWebServer starts an httptest.Server using webMux.
func newWebServer(t *testing.T, csrfToken string, statusFor map[string]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(webMux(t, csrfToken, statusFor))
	t.Cleanup(srv.Close)
	return srv
}

// commitEntry is one entry in the fake /commits list response.
type commitEntry struct {
	Commit struct {
		Author struct {
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`
	Author *loginEntry `json:"author"`
}

// loginEntry is the top-level author object (nullable in real GitHub API).
type loginEntry struct {
	Login string `json:"login"`
}

// apiMux builds an http.ServeMux that fakes the GitHub REST API. The
// emailToLogin map drives commit-author resolution (nil means no linked
// account).
//
// It serves:
//
//	GET    /user                            — returns {"login":"testowner"}
//	POST   /user/repos                      — creates a repo named "test-repo-name"
//	PUT    /repos/{owner}/{repo}/contents/* — file-create (201 Created)
//	GET    /repos/{owner}/{repo}/commits    — returns commits from emailToLogin
//	DELETE /repos/{owner}/{repo}            — succeeds (204 No Content)
func apiMux(t *testing.T, token string, emailToLogin map[string]*string, deleteStatus int) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()

	// Verify the token is sent as Bearer on every request.
	checkAuth := func(t *testing.T, r *http.Request) bool {
		t.Helper()
		auth := r.Header.Get("Authorization")
		return auth == "Bearer "+token
	}

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"login":"testowner"}`)
	})

	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"name":"test-repo-name","default_branch":"main"}`)
	})

	// /repos/{owner}/{repo}/contents/{file} — accepts PUT, returns 201
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(t, r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Distinguish commits (GET) from delete (DELETE) from contents (PUT).
		path := r.URL.Path
		switch {
		case r.Method == http.MethodDelete:
			if deleteStatus == 0 {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(deleteStatus)
			}
		case r.Method == http.MethodGet && strings.Contains(path, "/commits"):
			w.Header().Set("Content-Type", "application/json")
			commits := make([]commitEntry, 0, len(emailToLogin))
			for email, login := range emailToLogin {
				ce := commitEntry{}
				ce.Commit.Author.Email = email
				if login != nil {
					ce.Author = &loginEntry{Login: *login}
				}
				commits = append(commits, ce)
			}
			_ = json.NewEncoder(w).Encode(commits)
		case r.Method == http.MethodPut && strings.Contains(path, "/contents/"):
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	return mux
}

// newAPIServer starts an httptest.Server using apiMux.
func newAPIServer(t *testing.T, token string, emailToLogin map[string]*string, deleteStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(apiMux(t, token, emailToLogin, deleteStatus))
	t.Cleanup(srv.Close)
	return srv
}

// newTestEnumerator builds an Enumerator wired to the provided web+api test
// servers with noop sleep and deterministic naming to keep tests fast and
// repeatable.
func newTestEnumerator(t *testing.T, webSrv, apiSrv *httptest.Server, token string) *Enumerator {
	t.Helper()
	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err, "NewEnumerator must succeed")
	if webSrv != nil {
		e.webBaseURL = webSrv.URL
	}
	if apiSrv != nil {
		e.apiBaseURL = apiSrv.URL
	}
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName
	return e
}

// fakeRotatingProxyURL is a syntactically-valid, never-dialed socks5 proxy
// URL. NewEnumerator only treats --rotating-proxy as effective when a proxy
// is actually configured (Codex P2 fix: rotatingProxy && proxyURL != ""), so
// tests that only inspect the resulting Enumerator's fields (and never make a
// network request) can use this constant to exercise that gate honestly
// rather than asserting on the unexported field directly.
const fakeRotatingProxyURL = "socks5://127.0.0.1:1"

// newRotatingTestEnumerator is like newTestEnumerator but constructs the
// Enumerator with rotatingProxy=true and a real (non-empty) proxyURL, so the
// HTTP 403 retry-on-rotating-proxy path in postValidity is exercised — the
// Codex P2 fix makes --rotating-proxy effective only when a proxy is actually
// configured. webSrv itself is passed as the proxyURL: since Go's
// http.Transport sends plain-HTTP requests to a configured proxy in absolute
// form (see pkg/brutus/proxy_test.go's TestProxyAuthorization_EndToEnd) and
// the proxy target here is the same server as webBaseURL, webSrv's own mux
// handles the request directly — no separate forwarding proxy implementation
// is needed. existenceMaxRetries is overridden to the given small value so
// retry-exhaustion tests stay fast and deterministic (real rotating-proxy
// runs default to rotatingProxyMaxRetries, which is too large for a test).
func newRotatingTestEnumerator(t *testing.T, webSrv *httptest.Server, existenceMaxRetries int) *Enumerator {
	t.Helper()
	require.NotNil(t, webSrv, "newRotatingTestEnumerator requires a webSrv to double as the proxy target")
	e, err := NewEnumerator(webSrv.URL, 5*time.Second, "", true)
	require.NoError(t, err, "NewEnumerator must succeed")
	e.webBaseURL = webSrv.URL
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName
	e.existenceMaxRetries = existenceMaxRetries
	return e
}

// ---------------------------------------------------------------------------
// Existence tests: 422 → Exists=true, 200 → Exists=false
// ---------------------------------------------------------------------------

// TestExistence_422_ExistsTrue verifies that an HTTP 422 from the validity
// endpoint is mapped to Exists=true.
func TestExistence_422_ExistsTrue(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-token-abc", map[string]int{
		"alice@example.com": http.StatusUnprocessableEntity, // 422
	})
	e := newTestEnumerator(t, webSrv, nil, "")

	results := e.Enumerate(context.Background(), []string{"alice@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.True(t, results[0].Exists, "HTTP 422 must map to Exists=true (account already in use)")
	assert.Equal(t, "alice@example.com", results[0].Email)
}

// TestExistence_200_ExistsFalse verifies that an HTTP 200 from the validity
// endpoint is mapped to Exists=false.
func TestExistence_200_ExistsFalse(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-token-abc", map[string]int{
		"nobody@example.com": http.StatusOK, // 200
	})
	e := newTestEnumerator(t, webSrv, nil, "")

	results := e.Enumerate(context.Background(), []string{"nobody@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.False(t, results[0].Exists, "HTTP 200 must map to Exists=false (address available)")
}

// ---------------------------------------------------------------------------
// 429 retry: retries then succeeds
// ---------------------------------------------------------------------------

// TestExistence_429_RetryThenSucceed verifies that a 429 response causes a
// retry (with noopSleep so no actual delay), and that the subsequent 422
// response is correctly returned as Exists=true.
func TestExistence_429_RetryThenSucceed(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="csrf-abc">
</auto-check>
</body></html>`)
	})
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		email := r.FormValue("value")
		// Skip sanity-check address (it ends in @foobar.com — see establishSession).
		if strings.HasSuffix(email, "@foobar.com") {
			w.WriteHeader(http.StatusOK)
			return
		}
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests) // first call: 429
		} else {
			w.WriteHeader(http.StatusUnprocessableEntity) // second call: 422 → exists
		}
	})
	webSrv := httptest.NewServer(mux)
	t.Cleanup(webSrv.Close)

	e, err := NewEnumerator("", 5*time.Second, "", false)
	require.NoError(t, err)
	e.webBaseURL = webSrv.URL
	e.sleep = noopSleep
	e.newName = deterministicName

	results := e.Enumerate(context.Background(), []string{"retry@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error, "429 followed by 422 must not produce an error")
	assert.True(t, results[0].Exists, "after 429 retry, 422 must yield Exists=true")
	assert.Equal(t, int32(2), callCount.Load(), "exactly 2 calls to validity endpoint expected (1 retry)")
}

// ---------------------------------------------------------------------------
// Session parse failure → error on all results
// ---------------------------------------------------------------------------

// TestSessionParseFail_JoinPageMissingAutoCheck verifies that when the join
// page HTML does not contain the expected <auto-check> block, every Result
// carries the session error.
func TestSessionParseFail_JoinPageMissingAutoCheck(t *testing.T) {
	t.Parallel()

	// Serve a join page that has no auto-check block.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == joinPath {
			// HTML without the auto-check element.
			_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body><p>no auto-check here</p></body></html>`)
		}
	}))
	t.Cleanup(srv.Close)

	e, err := NewEnumerator("", 5*time.Second, "", false)
	require.NoError(t, err)
	e.webBaseURL = srv.URL
	e.sleep = noopSleep
	e.newName = deterministicName

	emails := []string{"a@example.com", "b@example.com"}
	results := e.Enumerate(context.Background(), emails, 1, 0, 0)

	require.Len(t, results, len(emails))
	for i, r := range results {
		assert.Error(t, r.Error, "result[%d] must carry a session error when CSRF parsing fails", i)
		// The error must mention the parsing failure; not a connection issue.
		assert.Contains(t, r.Error.Error(), "CSRF",
			"error for result[%d] must mention CSRF token not found", i)
	}
}

// ---------------------------------------------------------------------------
// Sanity-check: address that should not exist does not come back as 422
// ---------------------------------------------------------------------------

// TestSanityCheck_RandomAddressReturns200 is a behavioral test confirming that
// the sanity-check path inside establishSession does NOT block session setup
// when the random address correctly returns 200 (the expected case). The
// existence check then works normally.
func TestSanityCheck_RandomAddressReturns200(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-token-sanity", map[string]int{
		"alice@example.com": http.StatusUnprocessableEntity,
		// Random @foobar.com sanity check is not in map → defaults to 200 (OK)
	})
	e := newTestEnumerator(t, webSrv, nil, "")

	results := e.Enumerate(context.Background(), []string{"alice@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.True(t, results[0].Exists)
}

// ---------------------------------------------------------------------------
// Reveal: happy path — email → username mapping
// ---------------------------------------------------------------------------

// TestReveal_HappyPath verifies that Reveal creates a repo, pushes commits,
// lists them, and returns the correct email→username mapping. Also tests that
// a commit entry with a null (nil) top-level author is excluded from the map
// (no GitHub account linked to that email).
func TestReveal_HappyPath(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-happy"
	loginAlice := "alice-gh"
	// bob has nil top-level author → should be excluded from mapping.
	emailToLogin := map[string]*string{
		"alice@example.com": &loginAlice,
		"bob@example.com":   nil, // null author — no linked account
	}

	apiSrv := newAPIServer(t, token, emailToLogin, 0)
	e := newTestEnumerator(t, nil, apiSrv, token)

	mapping, err := e.Reveal(context.Background(), []string{"alice@example.com", "bob@example.com"})

	require.NoError(t, err)
	assert.Equal(t, "alice-gh", mapping["alice@example.com"],
		"alice's email must map to her login")
	_, bobPresent := mapping["bob@example.com"]
	assert.False(t, bobPresent,
		"bob's email must be excluded from mapping when top-level author is null")
}

// ---------------------------------------------------------------------------
// Reveal: empty token returns error
// ---------------------------------------------------------------------------

// TestReveal_EmptyToken verifies that Reveal returns an error immediately
// when called on an Enumerator with an empty token.
func TestReveal_EmptyToken(t *testing.T) {
	t.Parallel()

	// No servers needed — the error must be returned before any HTTP call.
	e := &Enumerator{
		token:       "",
		sleep:       noopSleep,
		newName:     deterministicName,
		settleDelay: 0,
		httpClient:  http.DefaultClient,
		webBaseURL:  webBaseURLDefault,
		apiBaseURL:  apiBaseURLDefault,
	}

	_, err := e.Reveal(context.Background(), []string{"a@example.com"})
	require.Error(t, err, "Reveal with empty token must return an error")
	assert.Contains(t, err.Error(), "token required",
		"error must mention that a token is required")
}

// ---------------------------------------------------------------------------
// Reveal: repo cleanup (DELETE) is always attempted
// ---------------------------------------------------------------------------

// TestReveal_DeleteAlwaysAttempted verifies that the repo DELETE is always
// called even when a mid-flow step (pushCommit) fails. The DELETE is the
// deferred cleanup that Reveal guarantees to call. We confirm the DELETE was
// attempted by having it return a status that would only be hit if called.
func TestReveal_DeleteAlwaysAttempted(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-delalways"

	var deleteCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"login":"testowner"}`)
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"name":"test-repo-name","default_branch":"main"}`)
	})
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodDelete:
			deleteCount.Add(1)
			w.WriteHeader(http.StatusNoContent) // delete succeeds
		case http.MethodPut:
			// pushCommit fails — forces early return from Reveal.
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err)
	e.apiBaseURL = apiSrv.URL
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName

	_, revErr := e.Reveal(context.Background(), []string{"alice@example.com"})
	require.Error(t, revErr, "Reveal must return an error when pushCommit fails")
	// The DELETE must have been called exactly once (deferred cleanup).
	assert.Equal(t, int32(1), deleteCount.Load(),
		"repo DELETE must be called exactly once as deferred cleanup, even when pushCommit fails")
}

// ---------------------------------------------------------------------------
// Reveal: repo cleanup (DELETE) survives a canceled reveal context
// ---------------------------------------------------------------------------

// TestReveal_DeletesEvenWhenContextCancelled verifies that the deferred repo
// DELETE is still sent even when the reveal ctx is canceled mid-flow. The
// settle-delay sleep cancels the ctx and returns context.Canceled, after
// createRepo and pushCommit succeed but before listCommitLogins runs, so the
// deferred cleanup fires with an already-canceled ctx. Because cleanup runs on
// a context detached from cancellation, the DELETE must still reach the API.
// Pre-fix (deferred deleteRepo reused the canceled ctx) => deleteCount == 0;
// with the fix => deleteCount == 1.
func TestReveal_DeletesEvenWhenContextCancelled(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-canceled-cleanup"

	var deleteCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"login":"testowner"}`)
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"name":"test-repo-name","default_branch":"main"}`)
	})
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			deleteCount.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `[]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err)
	e.apiBaseURL = apiSrv.URL
	e.newName = deterministicName
	e.settleDelay = 0

	ctx, cancel := context.WithCancel(context.Background())
	e.sleep = func(_ context.Context, _ time.Duration) error {
		cancel()
		return context.Canceled
	}

	_, revErr := e.Reveal(ctx, []string{"alice@example.com"})
	require.Error(t, revErr)

	assert.Equal(t, int32(1), deleteCount.Load(),
		"repo DELETE must still be sent even though the reveal ctx was canceled")
}

// ---------------------------------------------------------------------------
// Auth header: PAT is sent as Bearer <token> on every API call
// ---------------------------------------------------------------------------

// TestReveal_BearerTokenSentToAPI verifies that the PAT is sent as
// "Authorization: Bearer <token>" on every API request and is never embedded
// in any Result.Error text.
func TestReveal_BearerTokenSentToAPI(t *testing.T) {
	t.Parallel()

	const token = "ghp-secret-test-token-bearer-check"

	var badAuthCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			badAuthCount.Add(1)
		}
		_, _ = fmt.Fprintf(w, `{"login":"testowner"}`)
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			badAuthCount.Add(1)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"name":"test-repo-name","default_branch":"main"}`)
	})
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			badAuthCount.Add(1)
		}
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			// Return a mapping where alice has a linked account.
			loginAlice := "alice-gh"
			commits := []commitEntry{{}}
			commits[0].Commit.Author.Email = "alice@example.com"
			commits[0].Author = &loginEntry{Login: loginAlice}
			_ = json.NewEncoder(w).Encode(commits)
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err)
	e.apiBaseURL = apiSrv.URL
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName

	mapping, revErr := e.Reveal(context.Background(), []string{"alice@example.com"})
	require.NoError(t, revErr)

	// No API request must have used wrong auth.
	assert.Zero(t, badAuthCount.Load(),
		"every API request must send Authorization: Bearer %s", token)

	// Token must not appear in any result value.
	for email, login := range mapping {
		assert.NotContains(t, email, token,
			"token must not appear in result email")
		assert.NotContains(t, login, token,
			"token must not appear in result username")
	}
}

// ---------------------------------------------------------------------------
// Token never appears in Result.Error text
// ---------------------------------------------------------------------------

// TestReveal_TokenNotLeakedInError verifies that even when the API returns an
// unexpected error, the PAT value never appears in the error string returned
// by Reveal.
func TestReveal_TokenNotLeakedInError(t *testing.T) {
	t.Parallel()

	const token = "ghp-secret-should-never-appear-in-error"

	// /user returns 500 — forces an error immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err)
	e.apiBaseURL = srv.URL
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName

	_, revErr := e.Reveal(context.Background(), []string{"a@example.com"})
	require.Error(t, revErr, "a 500 on /user must cause Reveal to fail")
	assert.NotContains(t, revErr.Error(), token,
		"PAT must never appear in Reveal error text")
}

// ---------------------------------------------------------------------------
// Reveal: DELETE failure surfaces owner/repo for manual cleanup
// ---------------------------------------------------------------------------

// TestReveal_DeleteFailure_SurfacesRepoForManualCleanup is a focused regression
// test for the P1-A security fix: when the deferred repo DELETE fails, Reveal
// must (a) return a non-nil error, (b) include the full "owner/repo" path so
// the operator can remove the orphaned private repo manually, (c) still return
// the reveal mapping (the data already collected should not be thrown away), and
// (d) never include the PAT in the error text.
//
// The happy path succeeds (/user, /user/repos, pushCommit, listCommits all OK),
// but the DELETE returns HTTP 500. This is the path previously not exercised by
// any test.
func TestReveal_DeleteFailure_SurfacesRepoForManualCleanup(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-delete-failure"
	loginAlice := "alice-gh"
	emailToLogin := map[string]*string{
		"alice@example.com": &loginAlice,
	}

	// deleteStatus=500 makes the fake DELETE handler return 500, causing
	// deleteRepo to return an error and the deferred cleanup in Reveal to
	// annotate err with the owner/repo path.
	apiSrv := newAPIServer(t, token, emailToLogin, http.StatusInternalServerError)
	e := newTestEnumerator(t, nil, apiSrv, token)

	mapping, err := e.Reveal(context.Background(), []string{"alice@example.com"})

	// The delete failure must bubble up as a non-nil error.
	require.Error(t, err, "Reveal must return an error when the temp-repo DELETE fails")

	// The error must contain the full owner/repo path so the operator knows what
	// to delete manually. The fake /user handler returns login "testowner" and
	// deterministicName returns "test-repo-name", so the path is
	// "testowner/test-repo-name".
	assert.Contains(t, err.Error(), "testowner/test-repo-name",
		"error must contain the full owner/repo so the operator can delete it manually")

	// The reveal data (email→username mapping) collected before the failed
	// delete must still be returned — the operator should not lose their results
	// just because cleanup failed.
	assert.Equal(t, map[string]string{"alice@example.com": "alice-gh"}, mapping,
		"resolved email→username mapping must be returned even when DELETE fails")

	// The PAT must never appear in the error text.
	assert.NotContains(t, err.Error(), token,
		"PAT must never appear in Reveal error text")
}

// TestReveal_MidFlowErrorAndDeleteFailure_OriginalErrorJoined exercises the
// joined-error path in reveal.go: when Reveal has already failed mid-flow (e.g.
// pushCommit returns an error) AND the deferred DELETE also fails, the returned
// error must reference the original failure (joined via %w) rather than only
// reporting the delete error.
func TestReveal_MidFlowErrorAndDeleteFailure_OriginalErrorJoined(t *testing.T) {
	t.Parallel()

	const token = "ghp-test-token-dual-failure"

	// Build a custom mux: /user and /user/repos succeed, PUT /contents fails
	// (pushCommit error), and DELETE also fails (500).
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"login":"testowner"}`)
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"name":"test-repo-name","default_branch":"main"}`)
	})
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodDelete:
			// DELETE fails — this triggers the "both original and delete error" branch.
			w.WriteHeader(http.StatusInternalServerError)
		case http.MethodPut:
			// pushCommit fails — this is the original mid-flow error.
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	e, err := NewEnumerator("", 5*time.Second, token, false)
	require.NoError(t, err)
	e.apiBaseURL = apiSrv.URL
	e.settleDelay = 0
	e.sleep = noopSleep
	e.newName = deterministicName

	_, revErr := e.Reveal(context.Background(), []string{"alice@example.com"})

	// Must be non-nil — both original and delete error occurred.
	require.Error(t, revErr, "Reveal must return an error when both pushCommit and DELETE fail")

	// The joined error format from reveal.go is:
	//   "<original>; ADDITIONALLY failed to delete temp repo %q (delete it manually): <del err>"
	// The original pushCommit error mentions "pushing commit" and the joined
	// message must mention the owner/repo for manual cleanup.
	assert.Contains(t, revErr.Error(), "pushing commit",
		"joined error must still reference the original pushCommit failure")
	assert.Contains(t, revErr.Error(), "testowner/test-repo-name",
		"joined error must contain the owner/repo path for manual cleanup")

	// PAT must never appear in any error text.
	assert.NotContains(t, revErr.Error(), token,
		"PAT must never appear in Reveal error text")
}

// ---------------------------------------------------------------------------
// EnumerateWith: callback invoked once per email, results in input order
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Redirect regression: /join 302 → /signup, CSRF only on final page
// ---------------------------------------------------------------------------

// TestExistence_FollowsJoinRedirectForCSRF is a regression test for the bug
// where the existence client refused to follow redirects: the real
// github.com/join returns a 302 to /signup, and the CSRF authenticity_token
// (inside <auto-check src="/email_validity_checks">) only exists on that final
// page. When redirects were not followed, establishSession got an empty 302
// body and returned "CSRF authenticity token not found on join page", causing
// every existence check to fail.
//
// The existing web-server helper (webMux / newWebServer) serves the CSRF
// directly from /join with no redirect, so it did NOT catch this regression.
// This test stands up its own httptest server whose /join handler 302-redirects
// to /signup, which is the only place the CSRF HTML is served.
func TestExistence_FollowsJoinRedirectForCSRF(t *testing.T) {
	t.Parallel()

	const csrfToken = "csrf-redirect-test-token"

	// signupHTML is the minimal HTML that parseCSRFToken expects: an
	// <auto-check src="/email_validity_checks"> element containing a hidden
	// input whose value is the CSRF token.
	signupHTML := fmt.Sprintf(`<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)

	mux := http.NewServeMux()

	// /join responds with a 302 redirect to /signup (mirroring the real
	// github.com/join → github.com/signup flow). The CSRF token is NOT here.
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/signup", http.StatusFound)
	})

	// /signup serves the CSRF-bearing HTML. This is the final page the client
	// must land on after following the redirect.
	mux.HandleFunc("/signup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, signupHTML)
	})

	// /email_validity_checks returns 422 for the target email (account exists)
	// and 200 for everything else (including the sanity-check @foobar.com address).
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		email := r.FormValue("value")
		if email == "target@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422 → exists
		} else {
			w.WriteHeader(http.StatusOK) // 200 → available (sanity-check passes)
		}
	})

	redirectSrv := httptest.NewServer(mux)
	t.Cleanup(redirectSrv.Close)

	e := newTestEnumerator(t, redirectSrv, nil, "")

	results := e.Enumerate(context.Background(), []string{"target@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error,
		"establishSession must succeed by following the /join → /signup redirect to find the CSRF token")
	assert.True(t, results[0].Exists,
		"HTTP 422 from validity endpoint must map to Exists=true")
}

// ---------------------------------------------------------------------------
// EnumerateWith: callback invoked once per email, results in input order
// ---------------------------------------------------------------------------

// TestEnumerateWith_CallbackSerializationAndOrder verifies that onResult is
// called exactly once per email (under concurrent workers) and that the
// returned slice preserves input order.
func TestEnumerateWith_CallbackSerializationAndOrder(t *testing.T) {
	t.Parallel()

	emails := []string{
		"a@example.com",
		"b@example.com",
		"c@example.com",
		"d@example.com",
	}

	// a@ and c@ exist (422); b@ and d@ do not (200).
	statusFor := map[string]int{
		"a@example.com": http.StatusUnprocessableEntity,
		"b@example.com": http.StatusOK,
		"c@example.com": http.StatusUnprocessableEntity,
		"d@example.com": http.StatusOK,
	}
	webSrv := newWebServer(t, "csrf-order-test", statusFor)
	e := newTestEnumerator(t, webSrv, nil, "")

	var cbEmails []string
	results := e.EnumerateWith(
		context.Background(),
		emails,
		4,
		0,
		0,
		func(r Result) {
			cbEmails = append(cbEmails, r.Email)
		},
	)

	// Returned slice must be one-per-input-email.
	require.Len(t, results, len(emails))

	// Callback must be invoked exactly once per email.
	assert.Len(t, cbEmails, len(emails),
		"onResult callback must be called exactly once per email")

	// Returned results must be in input order.
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email,
			"result[%d] must correspond to input email[%d]", i, i)
	}

	// Existence results must match the configured status map.
	assert.True(t, results[0].Exists, "a@ (422) must be Exists=true")
	assert.False(t, results[1].Exists, "b@ (200) must be Exists=false")
	assert.True(t, results[2].Exists, "c@ (422) must be Exists=true")
	assert.False(t, results[3].Exists, "d@ (200) must be Exists=false")
}

// ---------------------------------------------------------------------------
// NewEnumerator: rotatingProxy flag wires correct backoff / retry constants
// ---------------------------------------------------------------------------

// TestNewEnumerator_RotatingProxy verifies that the rotatingProxy parameter
// controls which 429-retry constants are stored on the Enumerator.
// When false the defaults (rateLimitBackoff / maxRateLimitRetries) are used;
// when true the faster rotating-proxy constants are used.
func TestNewEnumerator_RotatingProxy(t *testing.T) {
	t.Parallel()

	t.Run("rotatingProxy=false uses default throttle", func(t *testing.T) {
		t.Parallel()
		e, err := NewEnumerator("", time.Second, "", false)
		require.NoError(t, err)
		assert.Equal(t, rateLimitBackoff, e.existenceBackoff,
			"existenceBackoff must equal rateLimitBackoff when rotatingProxy=false")
		assert.Equal(t, maxRateLimitRetries, e.existenceMaxRetries,
			"existenceMaxRetries must equal maxRateLimitRetries when rotatingProxy=false")
	})

	t.Run("rotatingProxy=true uses rotating-proxy throttle", func(t *testing.T) {
		t.Parallel()
		// rotatingProxy is only effective when a proxy is actually configured
		// (Codex P2 fix), so a proxyURL is required here to observe the
		// rotating-proxy throttle constants.
		e, err := NewEnumerator(fakeRotatingProxyURL, time.Second, "", true)
		require.NoError(t, err)
		assert.Equal(t, rotatingProxyBackoff, e.existenceBackoff,
			"existenceBackoff must equal rotatingProxyBackoff when rotatingProxy=true and a proxy is configured")
		assert.Equal(t, rotatingProxyMaxRetries, e.existenceMaxRetries,
			"existenceMaxRetries must equal rotatingProxyMaxRetries when rotatingProxy=true and a proxy is configured")
	})
}

// ---------------------------------------------------------------------------
// EnumerateWith: threads=0 must not deadlock (clamped to 1)
// ---------------------------------------------------------------------------

// TestEnumerateWith_ZeroThreadsDoesNotHang is a regression test for the bug
// where passing threads=0 to EnumerateWith made errgroup.SetLimit(0) block
// every g.Go(...) call forever, hanging enumeration indefinitely. EnumerateWith
// now clamps threads<=0 to 1 before calling SetLimit. This test bounds the call
// with a timeout so that if the clamp regresses, the test fails cleanly instead
// of hanging the whole suite.
func TestEnumerateWith_ZeroThreadsDoesNotHang(t *testing.T) {
	t.Parallel()

	emails := []string{"a@x.com", "b@x.com"}
	webSrv := newWebServer(t, "csrf-zero-threads", map[string]int{
		"a@x.com": http.StatusOK,
		"b@x.com": http.StatusOK,
	})
	e := newTestEnumerator(t, webSrv, nil, "")

	done := make(chan struct{})
	var results []Result
	go func() {
		results = e.Enumerate(context.Background(), emails, 0, 0, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Enumerate with threads=0 did not return within 10s — threads clamp missing (regressed)")
	}

	require.Len(t, results, len(emails))
	for i, r := range results {
		assert.NoError(t, r.Error, "result[%d] must complete without error against the mock server", i)
	}
}

// ---------------------------------------------------------------------------
// establishSession retry behavior: /join non-200 is retried, 200-no-token fails fast
// ---------------------------------------------------------------------------

// TestSession_RetriesOn403ThenSucceeds verifies that establishSession retries
// the /join fetch when GitHub's bot/rate detection returns a non-200 (e.g.
// HTTP 403) stub, and succeeds once /join starts returning the CSRF-bearing
// page.
func TestSession_RetriesOn403ThenSucceeds(t *testing.T) {
	t.Parallel()

	const csrfToken = "csrf-403-retry-token"
	var joinCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		n := joinCalls.Add(1)
		if n <= 2 {
			// Bot/rate-detection stub: non-200, no token.
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body>blocked</body></html>`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)
	})
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		email := r.FormValue("value")
		if email == "target@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422 → exists
		} else {
			w.WriteHeader(http.StatusOK) // 200 → available (sanity-check passes)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")

	results := e.Enumerate(context.Background(), []string{"target@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error, "establishSession must succeed after retrying past the 403 stubs")
	assert.True(t, results[0].Exists, "HTTP 422 from validity endpoint must map to Exists=true")
	assert.Equal(t, int32(3), joinCalls.Load(), "/join must be hit 3 times: 2 failed 403 attempts + 1 success")
}

// TestSession_403ExhaustsRetries verifies that when /join always returns a
// non-200 response, establishSession exhausts existenceMaxRetries and every
// email's Result carries an error mentioning the HTTP status. The session is
// established once per Enumerate batch, so /join must be hit exactly
// existenceMaxRetries+1 times regardless of how many emails are enumerated.
func TestSession_403ExhaustsRetries(t *testing.T) {
	t.Parallel()

	var joinCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		joinCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body>blocked</body></html>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")
	e.existenceMaxRetries = 2

	results := e.Enumerate(context.Background(), []string{"a@x.com", "b@x.com"}, 2, 0, 0)

	require.Len(t, results, 2)
	for i, r := range results {
		assert.Error(t, r.Error, "result[%d] must carry an error when /join always returns 403", i)
		if r.Error != nil {
			assert.Contains(t, r.Error.Error(), "join page returned HTTP 403",
				"result[%d] error must mention the join page HTTP status", i)
		}
	}
	assert.Equal(t, int32(3), joinCalls.Load(),
		"/join must be hit existenceMaxRetries+1=3 times total (session established once per batch, not per email)")
}

// TestSession_200NoTokenNotRetried verifies that a 200 response from /join
// whose HTML lacks a parseable CSRF token is NOT retried — it fails fast
// after a single attempt, since the endpoint contract has changed rather than
// GitHub applying transient bot/rate detection.
func TestSession_200NoTokenNotRetried(t *testing.T) {
	t.Parallel()

	var joinCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		joinCalls.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body><p>no auto-check here</p></body></html>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")

	results := e.Enumerate(context.Background(), []string{"a@x.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	assert.Error(t, results[0].Error, "a 200 join page with no CSRF token must produce an error")
	if results[0].Error != nil {
		assert.Contains(t, results[0].Error.Error(), "parsing join page",
			"error must mention join-page parsing failure")
	}
	assert.Equal(t, int32(1), joinCalls.Load(),
		"/join must be hit exactly once — a 200-with-no-token response must fail fast, not retry")
}

// TestExistence_SetsBrowserUserAgent is a regression test for the bug where the
// existence client sent no User-Agent header, so Go defaulted to
// "Go-http-client/…". GitHub returns HTTP 403 with a stub page (no CSRF token)
// to that UA, so establishSession → parseCSRFToken failed with "CSRF
// authenticity token not found on join page" on every run, recording every
// target email as an error.
//
// This test's /join handler mimics GitHub: it returns 403 when the request
// carries no User-Agent or a "Go-http-client" UA, and 200 with the CSRF-bearing
// auto-check block otherwise. Enumeration succeeding (no error, Exists=true)
// proves the request carried a browser UA. The test fails unless NewEnumerator
// wraps the client transport with enum.WithUserAgent.
func TestExistence_SetsBrowserUserAgent(t *testing.T) {
	t.Parallel()

	const csrfToken = "csrf-user-agent-test-token"

	signupHTML := fmt.Sprintf(`<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)

	mux := http.NewServeMux()

	// /join mimics GitHub: bot UAs (empty or "Go-http-client/…") get a 403 stub
	// with no CSRF token; a real browser UA gets the CSRF-bearing page.
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua == "" || strings.Contains(ua, "Go-http-client") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<html><body>Request blocked</body></html>`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, signupHTML)
	})

	// /email_validity_checks returns 422 for the target (account exists) and 200
	// for everything else (including the sanity-check @foobar.com address).
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("value") == "target@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422 → exists
		} else {
			w.WriteHeader(http.StatusOK) // 200 → available
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")

	results := e.Enumerate(context.Background(), []string{"target@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error,
		"establishSession must succeed by sending a browser User-Agent so /join returns the CSRF token instead of a 403 stub")
	assert.True(t, results[0].Exists,
		"HTTP 422 from validity endpoint must map to Exists=true")
}

// TestExistence_SetsAcceptHeader is a regression test for the bug where the
// existence client sent no Accept header on its requests, so Go's net/http
// defaulted to omitting it entirely. GitHub's signup page (/join) returns HTTP
// 403 to any request lacking an Accept header — proven empirically: the same
// client, in the same second, got HTTP 200 WITH an Accept header and HTTP 403
// WITHOUT one, across 25+ no-Accept samples that never succeeded.
//
// This test's /join and /email_validity_checks handlers record the Accept
// header they actually received. Enumeration succeeding (no error) plus the
// captured headers being non-empty proves both requests carry an Accept header
// — not just that the fake server happened to tolerate a missing one.
func TestExistence_SetsAcceptHeader(t *testing.T) {
	t.Parallel()

	const csrfToken = "csrf-accept-header-test-token"

	signupHTML := fmt.Sprintf(`<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)

	var joinAccept, validityAccept string

	mux := http.NewServeMux()

	// /join records the Accept header it received before serving the
	// CSRF-bearing page. In production, GitHub 403s this request when Accept
	// is absent — this fake server always serves the page, so the assertion
	// below is what actually catches a regression, not the handler.
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		joinAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, signupHTML)
	})

	// /email_validity_checks records the Accept header from the first request
	// it sees (the establishSession sanity check fires before the target
	// email's check, so this captures that first POST's header).
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if validityAccept == "" {
			validityAccept = r.Header.Get("Accept")
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("value") == "target@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422 → exists
		} else {
			w.WriteHeader(http.StatusOK) // 200 → available
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")

	results := e.Enumerate(context.Background(), []string{"target@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.True(t, results[0].Exists,
		"HTTP 422 from validity endpoint must map to Exists=true")

	assert.NotEmpty(t, joinAccept,
		"the join-page GET must carry a non-empty Accept header — GitHub 403s the join page when it is absent")
	assert.Contains(t, joinAccept, "text/html",
		"the join-page Accept header must include text/html so GitHub serves the real page, not a 403 stub")

	assert.Equal(t, "*/*", validityAccept,
		"the validity-check POST must carry Accept: */*")
}

// ---------------------------------------------------------------------------
// postValidity 403 handling: rotating-proxy retries, non-rotating fails fast
// ---------------------------------------------------------------------------

// validity403Mux builds an http.ServeMux for the postValidity 403-handling
// tests. /join always serves a valid CSRF-bearing page. /email_validity_checks
// always returns 200 for the sanity-check address (any @foobar.com email, per
// establishSession) so session setup never itself hits the 403 path under
// test; for every other email it increments targetCalls and returns 403 for
// the first failCount calls, then 422 (exists) afterward. A failCount of -1
// (or any count >= existenceMaxRetries+1) never recovers, modeling a
// permanently blocked IP.
func validity403Mux(t *testing.T, csrfToken string, targetCalls *atomic.Int32, failCount int) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)
	})
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(r.FormValue("value"), "@foobar.com") {
			w.WriteHeader(http.StatusOK) // sanity check always passes
			return
		}
		n := targetCalls.Add(1)
		if failCount < 0 || n <= int32(failCount) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity) // recovers to exists
	})
	return mux
}

// TestExistence_403RetriedToSuccess_RotatingProxy verifies that under
// --rotating-proxy, an HTTP 403 from the validity endpoint is retried (each
// retry modeling a fresh exit IP) rather than failing immediately, and that
// once the block lifts the underlying 422/200 result is still returned
// correctly.
func TestExistence_403RetriedToSuccess_RotatingProxy(t *testing.T) {
	t.Parallel()

	const target = "blocked@example.com"
	const failCount = 2
	var targetCalls atomic.Int32

	srv := httptest.NewServer(validity403Mux(t, "csrf-403-retry", &targetCalls, failCount))
	t.Cleanup(srv.Close)

	e := newRotatingTestEnumerator(t, srv, failCount+2) // retry budget covers failCount

	results := e.Enumerate(context.Background(), []string{target}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error,
		"403s must be retried to success under --rotating-proxy, not surfaced as an error")
	assert.True(t, results[0].Exists, "422 after the retries succeed must map to Exists=true")
	assert.Equal(t, int32(failCount+1), targetCalls.Load(),
		"validity endpoint must be hit failCount+1 times: failCount 403s + 1 recovering 422")
}

// TestExistence_403FailsFast_NonRotatingProxy verifies that without
// --rotating-proxy, an HTTP 403 from the validity endpoint is NOT retried: it
// fails immediately with the generic "unexpected status" error (same as any
// other unhandled status code), and the validity endpoint is hit exactly once.
func TestExistence_403FailsFast_NonRotatingProxy(t *testing.T) {
	t.Parallel()

	const target = "blocked@example.com"
	var targetCalls atomic.Int32

	// failCount=-1: the handler would always return 403 for the target if ever
	// called more than once, so a second call would also prove the (absent)
	// retry happened; targetCalls asserts it was called exactly once regardless.
	srv := httptest.NewServer(validity403Mux(t, "csrf-403-failfast", &targetCalls, -1))
	t.Cleanup(srv.Close)

	// newTestEnumerator always builds with rotatingProxy=false.
	e := newTestEnumerator(t, srv, nil, "")

	results := e.Enumerate(context.Background(), []string{target}, 1, 0, 0)

	require.Len(t, results, 1)
	require.Error(t, results[0].Error,
		"a 403 from the validity endpoint in non-rotating mode must be surfaced as an error")
	assert.Contains(t, results[0].Error.Error(), "unexpected status 403",
		"non-rotating 403 must fail with the generic unexpected-status error, not a retry-exhaustion error")
	assert.Equal(t, int32(1), targetCalls.Load(),
		"validity endpoint must be hit exactly once — non-rotating mode must never retry a 403")
}

// TestExistence_403ExhaustsRetries_RotatingProxy verifies that under
// --rotating-proxy, when the validity endpoint returns 403 on every attempt
// (the block never lifts), postValidity retries up to existenceMaxRetries and
// then returns the retry-exhaustion error, having hit the endpoint
// existenceMaxRetries+1 times in total.
func TestExistence_403ExhaustsRetries_RotatingProxy(t *testing.T) {
	t.Parallel()

	const target = "blocked@example.com"
	const maxRetries = 2
	var targetCalls atomic.Int32

	// failCount=-1: 403 for every call to the target email, so retries never
	// recover and existenceMaxRetries is exhausted.
	srv := httptest.NewServer(validity403Mux(t, "csrf-403-exhaust", &targetCalls, -1))
	t.Cleanup(srv.Close)

	e := newRotatingTestEnumerator(t, srv, maxRetries)

	results := e.Enumerate(context.Background(), []string{target}, 1, 0, 0)

	require.Len(t, results, 1)
	require.Error(t, results[0].Error,
		"exhausting all retries on a persistent 403 under --rotating-proxy must produce an error")
	assert.Contains(t, results[0].Error.Error(), "validity check blocked (HTTP 403) after",
		"error must report retry exhaustion, not the generic unexpected-status error")
	assert.Equal(t, int32(maxRetries+1), targetCalls.Load(),
		"validity endpoint must be hit existenceMaxRetries+1 times: the initial attempt plus every retry")
}

// ---------------------------------------------------------------------------
// NewEnumerator: rotatingProxy disables HTTP keep-alives (fresh exit IP)
// ---------------------------------------------------------------------------

// closeObservingWebServer starts a fake GitHub web server whose
// /email_validity_checks handler records, in sawClose, whether the inbound
// request for the (non-sanity-check) target email carried r.Close == true —
// i.e. whether the client sent "Connection: close" — then returns 200
// (available) so enumeration completes successfully regardless of the
// keep-alive setting under test.
func closeObservingWebServer(t *testing.T, sawClose *atomic.Bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="csrf-keepalive-test">
</auto-check>
</body></html>`)
	})
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasSuffix(r.FormValue("value"), "@foobar.com") {
			sawClose.Store(r.Close)
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestNewEnumerator_RotatingProxyDisablesKeepAlives verifies the behavioral
// effect of the DisableKeepAlives wiring in NewEnumerator: under
// rotatingProxy=true every existence request must carry "Connection: close"
// (observed server-side as http.Request.Close == true) so each retry opens a
// fresh TCP connection — and thus a fresh proxy exit IP — instead of reusing a
// pooled, already-blocked connection. Under rotatingProxy=false, connections
// must be kept alive as normal (r.Close == false).
//
// This test goes through NewEnumerator directly so the real *http.Transport
// built by brutus.NewHTTPClientWithProxy is exercised, rather than asserting
// on the unexported field directly. The rotatingProxy=true case must supply a
// non-empty proxyURL — NewEnumerator only treats --rotating-proxy as
// effective when a proxy is actually configured (Codex P2 fix) — so it passes
// webSrv itself as the proxyURL: Go's http.Transport sends plain-HTTP
// requests to a configured proxy in absolute form (see pkg/brutus/proxy_test.go's
// TestProxyAuthorization_EndToEnd), and since the proxy target here is the
// same server as webBaseURL, webSrv's own mux handles the request directly —
// no separate forwarding proxy implementation is needed.
func TestNewEnumerator_RotatingProxyDisablesKeepAlives(t *testing.T) {
	t.Parallel()

	t.Run("rotatingProxy=true sends Connection: close", func(t *testing.T) {
		t.Parallel()

		var sawClose atomic.Bool
		webSrv := closeObservingWebServer(t, &sawClose)

		e, err := NewEnumerator(webSrv.URL, 5*time.Second, "", true)
		require.NoError(t, err)
		e.webBaseURL = webSrv.URL
		e.sleep = noopSleep
		e.newName = deterministicName

		results := e.Enumerate(context.Background(), []string{"alice@example.com"}, 1, 0, 0)

		require.Len(t, results, 1)
		require.NoError(t, results[0].Error, "enumeration against the fake server must succeed")
		assert.True(t, sawClose.Load(),
			"rotatingProxy=true must set DisableKeepAlives so requests carry Connection: close (r.Close == true)")
	})

	t.Run("rotatingProxy=false keeps connections alive", func(t *testing.T) {
		t.Parallel()

		var sawClose atomic.Bool
		webSrv := closeObservingWebServer(t, &sawClose)

		e, err := NewEnumerator("", 5*time.Second, "", false)
		require.NoError(t, err)
		e.webBaseURL = webSrv.URL
		e.sleep = noopSleep
		e.newName = deterministicName

		results := e.Enumerate(context.Background(), []string{"alice@example.com"}, 1, 0, 0)

		require.Len(t, results, 1)
		require.NoError(t, results[0].Error, "enumeration against the fake server must succeed")
		assert.False(t, sawClose.Load(),
			"rotatingProxy=false must NOT set DisableKeepAlives — connections must be kept alive (r.Close == false)")
	})
}

// ---------------------------------------------------------------------------
// NewEnumerator: --rotating-proxy without --proxy is not effectively rotating
// ---------------------------------------------------------------------------

// TestNewEnumerator_RotatingProxyRequiresProxy is a regression test for a
// Codex P2 fix: --rotating-proxy without --proxy connects directly, so
// treating it as rotating caused up to rotatingProxyMaxRetries (15) pointless
// same-IP retries on every blocked request. NewEnumerator now computes the
// effective rotating flag as rotatingProxy && proxyURL != "", so a bare
// --rotating-proxy (no proxy configured) must behave exactly like
// rotatingProxy=false: the rotatingProxy field is false and the tuning
// (existenceMaxRetries) falls back to maxRateLimitRetries. Configuring both
// flags together must still enable the rotating behavior and its faster
// retry budget.
func TestNewEnumerator_RotatingProxyRequiresProxy(t *testing.T) {
	t.Parallel()

	t.Run("rotatingProxy=true without a proxy is not effective", func(t *testing.T) {
		t.Parallel()

		e, err := NewEnumerator("", time.Second, "", true)
		require.NoError(t, err)
		assert.False(t, e.rotatingProxy,
			"rotatingProxy field must be false when --rotating-proxy is set but no proxyURL is configured")
		assert.Equal(t, maxRateLimitRetries, e.existenceMaxRetries,
			"existenceMaxRetries must fall back to the non-rotating default (maxRateLimitRetries) without a proxy")
	})

	t.Run("rotatingProxy=true with a proxy is effective", func(t *testing.T) {
		t.Parallel()

		e, err := NewEnumerator("socks5://127.0.0.1:1080", time.Second, "", true)
		require.NoError(t, err)
		assert.True(t, e.rotatingProxy,
			"rotatingProxy field must be true when --rotating-proxy is set and a proxyURL is configured")
		assert.Equal(t, rotatingProxyMaxRetries, e.existenceMaxRetries,
			"existenceMaxRetries must use the rotating-proxy tuning (rotatingProxyMaxRetries) when a proxy is configured")
	})
}
