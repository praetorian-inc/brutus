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
		e, err := NewEnumerator("", time.Second, "", true)
		require.NoError(t, err)
		assert.Equal(t, rotatingProxyBackoff, e.existenceBackoff,
			"existenceBackoff must equal rotatingProxyBackoff when rotatingProxy=true")
		assert.Equal(t, rotatingProxyMaxRetries, e.existenceMaxRetries,
			"existenceMaxRetries must equal rotatingProxyMaxRetries when rotatingProxy=true")
	})
}
