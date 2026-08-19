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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Persistent reveal repo (SetRevealRepo)
//
// These tests exercise the opt-in mode in which RevealWith REUSES a named
// private repo rather than creating and deleting a throwaway one per call. The
// recording server below counts every route reveal touches, so each test can
// assert not just the returned mapping but the request pattern — which is the
// whole point of the mode (no repo churn, no delete, a bounded commit listing).
// ---------------------------------------------------------------------------

// revealRecorder records the requests a reveal run made against the fake API.
type revealRecorder struct {
	mu sync.Mutex

	repoReads     int          // GET /repos/{owner}/{repo}
	repoCreates   int          // POST /user/repos
	repoDeletes   int          // DELETE /repos/{owner}/{repo}
	pushes        int          // PUT /repos/{owner}/{repo}/contents/{file}
	pushPaths     []string     // the {file} segment of each PUT, in request order
	commitQueries []url.Values // one per GET /repos/{owner}/{repo}/commits page

	createNames []string // request bodies' "name" for each POST /user/repos
}

func (r *revealRecorder) snapshot() revealRecorder {
	r.mu.Lock()
	defer r.mu.Unlock()
	queries := make([]url.Values, len(r.commitQueries))
	copy(queries, r.commitQueries)
	names := make([]string, len(r.createNames))
	copy(names, r.createNames)
	paths := make([]string, len(r.pushPaths))
	copy(paths, r.pushPaths)
	return revealRecorder{
		repoReads:     r.repoReads,
		repoCreates:   r.repoCreates,
		repoDeletes:   r.repoDeletes,
		pushes:        r.pushes,
		pushPaths:     paths,
		commitQueries: queries,
		createNames:   names,
	}
}

// revealServerOpts configures the fake GitHub API for one test.
type revealServerOpts struct {
	// owner is the login returned by GET /user.
	owner string

	// repoReadStatuses are the statuses GET /repos/{owner}/{repo} answers with,
	// in order; the final entry is reused once exhausted. Empty means 200.
	repoReadStatuses []int
	// repoReadBranch is the default_branch returned on a 200 repo read.
	repoReadBranch string

	// createStatus/createBody are the response to POST /user/repos. Zero status
	// means 201 with a default body.
	createStatus int
	createBody   string

	// commitPages are the commit listings returned for pages 1..N. A request for
	// a page beyond the slice gets an empty array.
	commitPages [][]fakeCommit

	// pushStatuses are the statuses PUT /repos/{owner}/{repo}/contents/{file}
	// answers with, in order; the final entry is reused once exhausted. Empty
	// means 201 Created (the prior hardcoded behavior, unchanged for every
	// existing caller of this helper).
	pushStatuses []int
}

// fakeCommit is one entry of the commits listing. login == "" renders the
// top-level author as null, i.e. an email with no linked GitHub account.
type fakeCommit struct {
	email string
	login string
}

// newRevealServer starts a fake GitHub API that records what reveal does to it.
func newRevealServer(t *testing.T, token string, opts *revealServerOpts) (*httptest.Server, *revealRecorder) {
	t.Helper()

	if opts.owner == "" {
		opts.owner = "testowner"
	}
	if opts.repoReadBranch == "" {
		opts.repoReadBranch = "main"
	}

	rec := &revealRecorder{}
	mux := http.NewServeMux()

	authOK := func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer "+token
	}

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"login":%q}`, opts.owner)
	})

	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var payload struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)

		rec.mu.Lock()
		rec.repoCreates++
		rec.createNames = append(rec.createNames, payload.Name)
		rec.mu.Unlock()

		status := opts.createStatus
		if status == 0 {
			status = http.StatusCreated
		}
		body := opts.createBody
		if body == "" {
			body = fmt.Sprintf(`{"name":%q,"default_branch":"main"}`, payload.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	})

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodDelete:
			rec.mu.Lock()
			rec.repoDeletes++
			rec.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			rec.mu.Lock()
			rec.pushes++
			n := rec.pushes
			if idx := strings.Index(r.URL.Path, "/contents/"); idx >= 0 {
				rec.pushPaths = append(rec.pushPaths, r.URL.Path[idx+len("/contents/"):])
			}
			rec.mu.Unlock()

			status := http.StatusCreated
			if len(opts.pushStatuses) > 0 {
				idx := n - 1
				if idx >= len(opts.pushStatuses) {
					idx = len(opts.pushStatuses) - 1
				}
				status = opts.pushStatuses[idx]
			}
			w.WriteHeader(status)

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/commits"):
			rec.mu.Lock()
			rec.commitQueries = append(rec.commitQueries, r.URL.Query())
			page := len(rec.commitQueries)
			rec.mu.Unlock()

			var entries []fakeCommit
			if page >= 1 && page <= len(opts.commitPages) {
				entries = opts.commitPages[page-1]
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, renderCommits(entries))

		case r.Method == http.MethodGet:
			rec.mu.Lock()
			rec.repoReads++
			n := rec.repoReads
			rec.mu.Unlock()

			status := http.StatusOK
			if len(opts.repoReadStatuses) > 0 {
				idx := n - 1
				if idx >= len(opts.repoReadStatuses) {
					idx = len(opts.repoReadStatuses) - 1
				}
				status = opts.repoReadStatuses[idx]
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"default_branch":%q}`, opts.repoReadBranch)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rec
}

// renderCommits marshals fake commits into the shape listCommitLogins decodes.
func renderCommits(entries []fakeCommit) string {
	type authorEntry struct {
		Login string `json:"login"`
	}
	type commitOut struct {
		Commit struct {
			Author struct {
				Email string `json:"email"`
			} `json:"author"`
		} `json:"commit"`
		Author *authorEntry `json:"author"`
	}

	out := make([]commitOut, 0, len(entries))
	for _, e := range entries {
		var c commitOut
		c.Commit.Author.Email = e.email
		if e.login != "" {
			c.Author = &authorEntry{Login: e.login}
		}
		out = append(out, c)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// newPersistentEnumerator builds a test Enumerator pointed at srv, in
// persistent-repo mode under the given repo name.
func newPersistentEnumerator(t *testing.T, srv *httptest.Server, token, repo string) *Enumerator {
	t.Helper()
	e := newTestEnumerator(t, nil, srv, token)
	require.NoError(t, e.SetRevealRepo(repo), "SetRevealRepo must accept a valid name")
	return e
}

// ---------------------------------------------------------------------------
// SetRevealRepo: name validation
// ---------------------------------------------------------------------------

// TestSetRevealRepo_AcceptsValidNames verifies the names GitHub itself allows
// are accepted and actually switch the enumerator into persistent mode.
func TestSetRevealRepo_AcceptsValidNames(t *testing.T) {
	t.Parallel()

	names := []string{
		"guard-osint-reveal",
		"reveal_repo",
		"reveal.repo",
		"Reveal123",
		"a",
		strings.Repeat("a", repoNameMaxLen),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEnumerator("", 5*time.Second, "ghp-token", false)
			require.NoError(t, err)

			require.NoError(t, e.SetRevealRepo(name), "valid name must be accepted")
			assert.Equal(t, name, e.revealRepo, "accepted name must be stored")
		})
	}
}

// TestSetRevealRepo_RejectsInvalidNames verifies invalid names are refused
// before any HTTP request is issued — a bad name must not become a bad request.
func TestSetRevealRepo_RejectsInvalidNames(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":         "",
		"too long":      strings.Repeat("a", repoNameMaxLen+1),
		"dot":           ".",
		"dot dot":       "..",
		"slash":         "owner/repo",
		"space":         "reveal repo",
		"path escape":   "../../etc/passwd",
		"query char":    "repo?x=1",
		"percent":       "repo%2f",
		"non ascii":     "repö",
		"leading slash": "/repo",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEnumerator("", 5*time.Second, "ghp-token", false)
			require.NoError(t, err)

			err = e.SetRevealRepo(value)
			require.Error(t, err, "invalid name %q must be rejected", value)
			assert.Empty(t, e.revealRepo, "a rejected name must not be stored")
		})
	}
}

// TestSetRevealRepo_RejectionLeavesPreviousModeIntact verifies a failed call
// does not clear a name that was already accepted — the documented contract is
// that the enumerator keeps its previous mode on error.
func TestSetRevealRepo_RejectionLeavesPreviousModeIntact(t *testing.T) {
	t.Parallel()

	e, err := NewEnumerator("", 5*time.Second, "ghp-token", false)
	require.NoError(t, err)

	require.NoError(t, e.SetRevealRepo("good-name"))
	require.Error(t, e.SetRevealRepo("bad name"))

	assert.Equal(t, "good-name", e.revealRepo, "the previously accepted name must survive a rejected one")
}

// ---------------------------------------------------------------------------
// Persistent mode: repo resolution
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_ReusesExistingRepo is the steady state: the repo is
// already there, so reveal READS it (one request, which also yields the default
// branch), creates nothing, and deletes nothing.
func TestRevealWith_Persistent_ReusesExistingRepo(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-reuse"
	const repo = "guard-osint-reveal"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		repoReadBranch:   "trunk",
		commitPages: [][]fakeCommit{
			{{email: "alice@example.com", login: "alice-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, repo)

	mapping, err := e.RevealWith(context.Background(), []string{"alice@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"alice@example.com": "alice-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, 1, got.repoReads, "an existing repo is resolved with a single read")
	assert.Zero(t, got.repoCreates, "an existing repo must not be re-created")
	assert.Zero(t, got.repoDeletes, "persistent mode must never delete the repo")
	assert.Equal(t, 1, got.pushes, "one commit per email")

	require.Len(t, got.commitQueries, 1)
	assert.Equal(t, "trunk", got.commitQueries[0].Get("sha"),
		"the listing must use the branch reported by the repo read, not a hardcoded default")
}

// TestRevealWith_Persistent_CreatesRepoWhenAbsent covers the first run for a
// given name: the read 404s, so reveal creates the repo — and still never
// deletes it.
func TestRevealWith_Persistent_CreatesRepoWhenAbsent(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-create"
	const repo = "guard-osint-reveal"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusNotFound},
		createStatus:     http.StatusCreated,
		createBody:       `{"name":"guard-osint-reveal","default_branch":"main"}`,
		commitPages: [][]fakeCommit{
			{{email: "bob@example.com", login: "bob-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, repo)

	mapping, err := e.RevealWith(context.Background(), []string{"bob@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"bob@example.com": "bob-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, 1, got.repoCreates, "an absent repo is created once")
	require.Len(t, got.createNames, 1)
	assert.Equal(t, repo, got.createNames[0], "the repo must be created under the caller's name")
	assert.Zero(t, got.repoDeletes, "persistent mode must never delete the repo")
}

// TestRevealWith_Persistent_Tolerates422AlreadyExists covers the race in which
// the repo appears between our read and our create: GitHub answers 422 "already
// exists", which is a success for this mode, and reveal re-reads to learn the
// branch.
func TestRevealWith_Persistent_Tolerates422AlreadyExists(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-race"
	const repo = "guard-osint-reveal"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		// First read: absent. Second read (after the 422): present.
		repoReadStatuses: []int{http.StatusNotFound, http.StatusOK},
		repoReadBranch:   "trunk",
		createStatus:     http.StatusUnprocessableEntity,
		createBody: `{"message":"Repository creation failed.","errors":[` +
			`{"resource":"Repository","field":"name","message":"name already exists on this account"}]}`,
		commitPages: [][]fakeCommit{
			{{email: "carol@example.com", login: "carol-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, repo)

	mapping, err := e.RevealWith(context.Background(), []string{"carol@example.com"}, nil)
	require.NoError(t, err, "a 422 naming an existing repo is success in persistent mode")
	assert.Equal(t, map[string]string{"carol@example.com": "carol-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, 2, got.repoReads, "the race is resolved by re-reading the repo")
	assert.Zero(t, got.repoDeletes)
	require.Len(t, got.commitQueries, 1)
	assert.Equal(t, "trunk", got.commitQueries[0].Get("sha"),
		"the re-read must supply the branch")
}

// TestRevealWith_Persistent_422OtherReasonFails verifies a 422 that is NOT
// "already exists" — an exhausted repository quota, say — still fails loudly
// rather than being swallowed as reuse.
func TestRevealWith_Persistent_422OtherReasonFails(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-422-other"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusNotFound},
		createStatus:     http.StatusUnprocessableEntity,
		createBody: `{"message":"Repository creation failed.","errors":[` +
			`{"resource":"Repository","field":"name","message":"is over your quota"}]}`,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"dave@example.com"}, nil)
	require.Error(t, err, "a 422 for any other reason must not be treated as reuse")
	assert.Contains(t, err.Error(), "422")

	got := rec.snapshot()
	assert.Zero(t, got.pushes, "no commits may be pushed once repo resolution failed")
	assert.Zero(t, got.repoDeletes)
}

// TestRevealWith_Persistent_RepoReadErrorFails verifies a non-404 failure on the
// repo read aborts before any push, rather than falling through to a create.
func TestRevealWith_Persistent_RepoReadErrorFails(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-read-500"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusInternalServerError},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"erin@example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")

	got := rec.snapshot()
	assert.Zero(t, got.repoCreates, "a failed read must not be mistaken for an absent repo")
	assert.Zero(t, got.pushes)
}

// ---------------------------------------------------------------------------
// Persistent mode: the commit listing is bounded to THIS call
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_SendsSinceFloor is the load-bearing assertion of the
// whole mode: without ?since= a reused repo would be re-walked from its first
// commit on every call. The floor must sit just before the run, and be sent in
// the RFC3339 form GitHub expects.
func TestRevealWith_Persistent_SendsSinceFloor(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-since"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			{{email: "frank@example.com", login: "frank-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	before := time.Now()
	_, err := e.RevealWith(context.Background(), []string{"frank@example.com"}, nil)
	require.NoError(t, err)
	after := time.Now()

	got := rec.snapshot()
	require.Len(t, got.commitQueries, 1)

	raw := got.commitQueries[0].Get("since")
	require.NotEmpty(t, raw, "persistent mode must floor the listing with ?since=")

	since, parseErr := time.Parse(time.RFC3339, raw)
	require.NoError(t, parseErr, "since must be RFC3339, got %q", raw)

	// The floor is deliberately nudged into the past by revealSinceSkew to
	// tolerate clock drift between this host and GitHub, so it must land inside
	// [start-skew-1s, end] — early enough to include the pushes, never later.
	assert.False(t, since.After(after), "the floor must not be later than the run")
	assert.False(t, since.Before(before.Add(-revealSinceSkew).Add(-time.Second)),
		"the floor must not reach further back than the documented skew allowance")
}

// TestRevealWith_Ephemeral_SendsNoSince pins the default throwaway path: it must
// keep issuing exactly the commits query it always has. A throwaway repo is
// created empty, so it has no history to exclude and no reason to take on
// clock-skew risk.
func TestRevealWith_Ephemeral_SendsNoSince(t *testing.T) {
	t.Parallel()

	const token = "ghp-ephemeral-no-since"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		commitPages: [][]fakeCommit{
			{{email: "grace@example.com", login: "grace-gh"}},
		},
	})
	e := newTestEnumerator(t, nil, srv, token) // no SetRevealRepo — default mode

	mapping, err := e.RevealWith(context.Background(), []string{"grace@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"grace@example.com": "grace-gh"}, mapping)

	got := rec.snapshot()
	require.Len(t, got.commitQueries, 1)
	assert.Empty(t, got.commitQueries[0].Get("since"),
		"the throwaway path must not send since")
	assert.Equal(t, 1, got.repoCreates, "the throwaway path still creates its own repo")
	assert.Equal(t, 1, got.repoDeletes, "the throwaway path still deletes it")
	assert.Zero(t, got.repoReads, "the throwaway path has no repo to read")
}

// TestRevealWith_StopsPagingOnceEveryEmailResolved verifies the second bound on
// the listing: commits come back newest-first, so once every requested email has
// a login there is nothing further to learn and paging stops — even though a
// full page would otherwise imply another one.
func TestRevealWith_StopsPagingOnceEveryEmailResolved(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-earlystop"

	// A full page (commitsPerPage entries) that already resolves the only
	// requested email. Page 2 exists and would be fetched by a naive "keep going
	// while the page is full" loop.
	page1 := make([]fakeCommit, 0, commitsPerPage)
	page1 = append(page1, fakeCommit{email: "heidi@example.com", login: "heidi-gh"})
	for i := 1; i < commitsPerPage; i++ {
		page1 = append(page1, fakeCommit{
			email: fmt.Sprintf("old-%d@example.com", i),
			login: fmt.Sprintf("old-gh-%d", i),
		})
	}
	page2 := []fakeCommit{{email: "older@example.com", login: "older-gh"}}

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      [][]fakeCommit{page1, page2},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"heidi@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "heidi-gh", mapping["heidi@example.com"])
	assert.NotContains(t, mapping, "older@example.com",
		"page 2 must never have been fetched")

	got := rec.snapshot()
	assert.Len(t, got.commitQueries, 1,
		"paging must stop as soon as every requested email is resolved")
}

// TestRevealWith_PagesOnWhileAnEmailIsUnresolved is the counterpart: an email
// that is still missing must not be given up on while full pages remain, or the
// early stop would silently lose results.
func TestRevealWith_PagesOnWhileAnEmailIsUnresolved(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-pageon"

	// A full first page that does NOT contain the requested email.
	page1 := make([]fakeCommit, 0, commitsPerPage)
	for i := 0; i < commitsPerPage; i++ {
		page1 = append(page1, fakeCommit{
			email: fmt.Sprintf("other-%d@example.com", i),
			login: fmt.Sprintf("other-gh-%d", i),
		})
	}
	page2 := []fakeCommit{{email: "ivan@example.com", login: "ivan-gh"}}

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      [][]fakeCommit{page1, page2},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"ivan@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "ivan-gh", mapping["ivan@example.com"],
		"an unresolved email must keep the listing paging")

	got := rec.snapshot()
	assert.Len(t, got.commitQueries, 2, "paging must continue past a full page")
}

// TestRevealWith_UnlinkedEmailStopsAtShortPage verifies the terminating case for
// an email with no linked GitHub account: it never resolves, so the loop must
// fall back on the short-page condition rather than paging forever.
func TestRevealWith_UnlinkedEmailStopsAtShortPage(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-unlinked"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			// Short page, and the email's commit has a null author.
			{{email: "judy@example.com", login: ""}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"judy@example.com"}, nil)
	require.NoError(t, err)
	assert.NotContains(t, mapping, "judy@example.com",
		"an email with no linked account must be omitted, not invented")

	got := rec.snapshot()
	assert.Len(t, got.commitQueries, 1, "a short page ends the listing")
}
