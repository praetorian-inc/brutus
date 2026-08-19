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
	"strconv"
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
	pushBranches  []*string    // the "branch" field of each PUT body; nil means the key was absent
	commitQueries []url.Values // one per GET /repos/{owner}/{repo}/commits page

	createNames []string // request bodies' "name" for each POST /user/repos

	refReads   []string           // branch requested on each GET .../git/ref/heads/{branch}
	refCreates []refCreateRequest // ref+sha of each POST .../git/refs, in request order
	refDeletes []string           // branch requested on each DELETE .../git/refs/heads/{branch}
}

// refCreateRequest is one POST .../git/refs request body, as reveal.go sends
// it from startRunBranch: ref is "refs/heads/<name>" and sha is the base
// commit the new branch points at.
type refCreateRequest struct {
	ref string
	sha string
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
	branches := make([]*string, len(r.pushBranches))
	copy(branches, r.pushBranches)
	refReads := make([]string, len(r.refReads))
	copy(refReads, r.refReads)
	refCreates := make([]refCreateRequest, len(r.refCreates))
	copy(refCreates, r.refCreates)
	refDeletes := make([]string, len(r.refDeletes))
	copy(refDeletes, r.refDeletes)
	return revealRecorder{
		repoReads:     r.repoReads,
		repoCreates:   r.repoCreates,
		repoDeletes:   r.repoDeletes,
		pushes:        r.pushes,
		pushPaths:     paths,
		pushBranches:  branches,
		commitQueries: queries,
		createNames:   names,
		refReads:      refReads,
		refCreates:    refCreates,
		refDeletes:    refDeletes,
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
	// repoReadPrivate is the "private" value a 200 repo read reports. It
	// defaults to true — an existing persistent reveal repo is normally
	// private — so most tests need not set it; a test exercising the
	// public-repo-refusal path sets it to a pointer to false. Ignored when
	// repoReadOmitPrivateField is set.
	repoReadPrivate *bool
	// repoReadOmitPrivateField, when true, makes a 200 repo read omit the
	// "private" key entirely, exercising resolveRevealRepo's fail-closed
	// behavior for a response that never says either way.
	repoReadOmitPrivateField bool

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

	// commitsStatus, when non-zero, makes EVERY GET .../commits page answer
	// with this status instead of a rendered commitPages entry — used to
	// simulate a mid-flow listing failure after the push loop already
	// succeeded (e.g. to prove the run-branch delete still happens).
	commitsStatus int

	// refSHAStatuses are the statuses GET .../git/ref/heads/{branch} answers
	// with, in order; the final entry is reused once exhausted. Empty means a
	// single 200 reporting refSHA — i.e. the reveal repo already has a base
	// commit, so ensureBaseCommit need not initialize it. A test exercising
	// the empty-repo path scripts 404 or 409 for the first read.
	refSHAStatuses []int
	// refSHA is the commit SHA a 200 ref-read reports. Defaults to a constant
	// non-empty value when unset (refSHA's own decoding rejects an empty SHA,
	// so this must never be the zero value on a 200).
	refSHA string

	// refCreateStatuses are the statuses POST .../git/refs answers with, in
	// order; the final entry is reused once exhausted. Empty means a single
	// 201 Created — the run branch is created on the first attempt. A test
	// exercising the name-collision retry scripts one or more 422s.
	refCreateStatuses []int

	// refDeleteStatuses are the statuses DELETE .../git/refs/heads/{branch}
	// answers with, in order; the final entry is reused once exhausted. Empty
	// means a single 204 No Content.
	refDeleteStatuses []int
}

// defaultRefSHA is the commit SHA newRevealServer's ref-read route reports on
// a 200 when a test does not override revealServerOpts.refSHA.
const defaultRefSHA = "0000000000000000000000000000000000base0"

// scriptedStatus returns statuses[n-1] (n is the 1-based call count for the
// route), clamped to the last entry once the script is exhausted, or def when
// statuses is empty. It exists for the three new run-branch/base-commit routes
// added to newRevealServer, so their scripting logic is not copy-pasted three
// times; the pre-existing repoReadStatuses/pushStatuses routes are left as
// they were to avoid touching passing tests' surrounding code.
func scriptedStatus(statuses []int, n, def int) int {
	if len(statuses) == 0 {
		return def
	}
	idx := n - 1
	if idx >= len(statuses) {
		idx = len(statuses) - 1
	}
	return statuses[idx]
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
		// Ref delete (DELETE .../git/refs/heads/{branch}) must be checked BEFORE
		// the generic repo-delete case below: both are DELETE, and the repo
		// delete's path (.../repos/{owner}/{repo}) is a prefix of the ref
		// delete's, so this more specific match has to come first.
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/heads/"):
			idx := strings.Index(r.URL.Path, "/git/refs/heads/")
			branchEnc := r.URL.Path[idx+len("/git/refs/heads/"):]
			branch, _ := url.PathUnescape(branchEnc)

			rec.mu.Lock()
			rec.refDeletes = append(rec.refDeletes, branch)
			n := len(rec.refDeletes)
			rec.mu.Unlock()

			w.WriteHeader(scriptedStatus(opts.refDeleteStatuses, n, http.StatusNoContent))

		case r.Method == http.MethodDelete:
			rec.mu.Lock()
			rec.repoDeletes++
			rec.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		// Run-branch creation: POST .../git/refs, no branch segment in the path
		// (the new ref's name travels in the JSON body).
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var payload struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)

			rec.mu.Lock()
			rec.refCreates = append(rec.refCreates, refCreateRequest{ref: payload.Ref, sha: payload.SHA})
			n := len(rec.refCreates)
			rec.mu.Unlock()

			w.WriteHeader(scriptedStatus(opts.refCreateStatuses, n, http.StatusCreated))

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			var payload struct {
				Branch *string `json:"branch"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)

			rec.mu.Lock()
			rec.pushes++
			n := rec.pushes
			if idx := strings.Index(r.URL.Path, "/contents/"); idx >= 0 {
				rec.pushPaths = append(rec.pushPaths, r.URL.Path[idx+len("/contents/"):])
			}
			rec.pushBranches = append(rec.pushBranches, payload.Branch)
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
			if opts.commitsStatus != 0 {
				w.WriteHeader(opts.commitsStatus)
				return
			}

			query := r.URL.Query()
			rec.mu.Lock()
			rec.commitQueries = append(rec.commitQueries, query)
			rec.mu.Unlock()

			// Keyed off the request's own ?page= rather than the count of commit
			// requests seen so far: the latter would report page N correctly only
			// if the implementation happens to request pages 1..N in order with no
			// gaps or repeats, so an off-by-one in the real paging loop could go
			// undetected.
			page, convErr := strconv.Atoi(query.Get("page"))
			if convErr != nil || page < 1 {
				page = 1
			}

			var entries []fakeCommit
			if page <= len(opts.commitPages) {
				entries = opts.commitPages[page-1]
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, renderCommits(entries))

		// Base-commit ref read: GET .../git/ref/heads/{branch} (singular "ref"),
		// checked before the generic repo-read GET case below (which has no
		// further path constraint and would otherwise swallow this too).
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			idx := strings.Index(r.URL.Path, "/git/ref/heads/")
			branchEnc := r.URL.Path[idx+len("/git/ref/heads/"):]
			branch, _ := url.PathUnescape(branchEnc)

			rec.mu.Lock()
			rec.refReads = append(rec.refReads, branch)
			n := len(rec.refReads)
			rec.mu.Unlock()

			status := scriptedStatus(opts.refSHAStatuses, n, http.StatusOK)
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			sha := opts.refSHA
			if sha == "" {
				sha = defaultRefSHA
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"object":{"sha":%q}}`, sha)

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
			if opts.repoReadOmitPrivateField {
				_, _ = fmt.Fprintf(w, `{"default_branch":%q}`, opts.repoReadBranch)
				return
			}
			private := true
			if opts.repoReadPrivate != nil {
				private = *opts.repoReadPrivate
			}
			_, _ = fmt.Fprintf(w, `{"default_branch":%q,"private":%t}`, opts.repoReadBranch, private)

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

// boolPtr returns a pointer to b, for revealServerOpts.repoReadPrivate
// literals in test cases.
func boolPtr(b bool) *bool {
	return &b
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

	// The commit listing now reads THIS call's own run branch, not the repo's
	// default branch — that is the whole point of the run-branch redesign.
	require.Len(t, got.refCreates, 1, "exactly one run branch is created for this call")
	runBranch := strings.TrimPrefix(got.refCreates[0].ref, "refs/heads/")

	require.Len(t, got.commitQueries, 1)
	assert.Equal(t, runBranch, got.commitQueries[0].Get("sha"),
		"the listing must use this call's own run branch, not the repo's default branch")
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

	require.Len(t, got.refCreates, 1, "exactly one run branch is created for this call")
	runBranch := strings.TrimPrefix(got.refCreates[0].ref, "refs/heads/")

	require.Len(t, got.commitQueries, 1)
	assert.Equal(t, runBranch, got.commitQueries[0].Get("sha"),
		"the listing must use this call's own run branch")
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

// TestRevealWith_Persistent_422AlreadyExistsOnOtherFieldFails verifies
// repoNameTaken's field check: a 422 whose "already exists" message is
// attached to some field OTHER than "name" is a different rejection (a
// duplicate topic, say) and must be treated as a hard failure rather than
// read as "the repo we asked for already exists" — reusing that reasoning
// would push commits at a repo resolveRevealRepo never actually resolved.
func TestRevealWith_Persistent_422AlreadyExistsOnOtherFieldFails(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-422-other-field"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusNotFound},
		createStatus:     http.StatusUnprocessableEntity,
		createBody: `{"message":"Repository creation failed.","errors":[` +
			`{"resource":"Repository","field":"topic","message":"already exists on this repository"}]}`,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"dave@example.com"}, nil)
	require.Error(t, err, `an "already exists" message on a non-name field must not be read as reuse`)
	assert.Contains(t, err.Error(), "422")

	got := rec.snapshot()
	assert.Equal(t, 1, got.repoReads, "a rejected create must not trigger the reuse re-read")
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
// Persistent mode: an existing repo must be confirmed private before reuse
// ---------------------------------------------------------------------------
//
// Reveal writes every target email into commit metadata. A repo it did not
// just create itself is not one it can assume anything about, so
// resolveRevealRepo refuses to push to it unless GitHub's own response says
// private:true. A test that only checked the returned error would pass even
// if the implementation pushed the commits and THEN returned an error, which
// is precisely why every test below also asserts zero pushes.

// TestRevealWith_Persistent_RefusesReuseOfPublicRepo verifies that an existing
// repo GitHub reports as public is refused outright: RevealWith must error,
// the error must explain why, and — the assertion that actually matters —
// not one commit may have been pushed. Emails must never reach a public repo.
func TestRevealWith_Persistent_RefusesReuseOfPublicRepo(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-public-repo"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		repoReadPrivate:  boolPtr(false),
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"mallory@example.com"}, nil)
	require.Error(t, err, "a public existing repo must be refused")
	assert.Contains(t, err.Error(), "public",
		"the error must say why the repo was refused, not just that it failed")

	got := rec.snapshot()
	assert.Zero(t, got.pushes,
		"zero commits may reach a public repo — a passing error is not enough on its own")
	assert.Zero(t, got.repoCreates)
	assert.Zero(t, got.repoDeletes)
}

// TestRevealWith_Persistent_RefusesReuseWhenPrivacyUnknown verifies the
// fail-closed direction of the check: a repo read whose JSON omits "private"
// entirely must be refused exactly like a public one, rather than being
// treated as private by omission. "Could not confirm private" must never
// read as "is private".
func TestRevealWith_Persistent_RefusesReuseWhenPrivacyUnknown(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-privacy-unknown"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses:         []int{http.StatusOK},
		repoReadOmitPrivateField: true,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"mallory@example.com"}, nil)
	require.Error(t, err, "a repo read that never confirms privacy must be refused")
	assert.Contains(t, err.Error(), "private")

	got := rec.snapshot()
	assert.Zero(t, got.pushes, "no commits may be pushed when privacy could not be confirmed")
}

// TestRevealWith_Persistent_RaceRereadRefusesPublicRepo covers the 422 race
// path: the initial read 404s, the create loses the race with a 422 "already
// exists", and the RE-read that follows reports the repo as public. That
// re-read result must be checked exactly like the direct-read path — the
// race must not become a way to skip the privacy check.
func TestRevealWith_Persistent_RaceRereadRefusesPublicRepo(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-race-public"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusNotFound, http.StatusOK},
		repoReadPrivate:  boolPtr(false),
		createStatus:     http.StatusUnprocessableEntity,
		createBody: `{"message":"Repository creation failed.","errors":[` +
			`{"resource":"Repository","field":"name","message":"name already exists on this account"}]}`,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"mallory@example.com"}, nil)
	require.Error(t, err, "the re-read after a 422 race must be privacy-checked too")
	assert.Contains(t, err.Error(), "public")

	got := rec.snapshot()
	assert.Equal(t, 2, got.repoReads, "the race path re-reads before the check runs")
	assert.Zero(t, got.pushes, "no commits may be pushed after a race onto a public repo")
	assert.Zero(t, got.repoDeletes)
}

// ---------------------------------------------------------------------------
// Persistent mode: the commit listing is bounded to THIS call
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_SendsNoSince pins the redesign's removal of
// ?since=: persistent mode no longer floors the commit listing by time at
// all — a reused repo's history is now bounded by giving every call its own
// branch (see the "run-branch model" tests below), not by a clock-based
// filter. Server-side clock skew between this host and GitHub is exactly the
// class of bug that approach removes, so its absence here is deliberate.
func TestRevealWith_Persistent_SendsNoSince(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-since"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			{{email: "frank@example.com", login: "frank-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"frank@example.com"}, nil)
	require.NoError(t, err)

	got := rec.snapshot()
	require.Len(t, got.commitQueries, 1)
	assert.Empty(t, got.commitQueries[0].Get("since"),
		"persistent mode must no longer send ?since= at all")

	// What replaced it: the listing is scoped to this call's own run branch.
	require.Len(t, got.refCreates, 1)
	runBranch := strings.TrimPrefix(got.refCreates[0].ref, "refs/heads/")
	assert.Equal(t, runBranch, got.commitQueries[0].Get("sha"),
		"the listing must be scoped by this call's run branch instead")
}

// TestRevealWith_Ephemeral_SendsNoSince pins the default throwaway path: it must
// keep issuing exactly the commits query it always has. A throwaway repo is
// created empty, so it has no history to exclude and no reason to take on
// clock-skew risk.
//
// This is also the regression guard for the run-branch redesign on the
// DEFAULT mode: the throwaway path must be completely untouched by it — no
// ref is ever created or deleted, and every push must omit the "branch" key
// exactly as it always has, so the request the throwaway flow sends is
// byte-for-byte what it was before persistent mode existed.
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

	assert.Empty(t, got.refCreates, "the throwaway path must never create a run branch")
	assert.Empty(t, got.refDeletes, "the throwaway path must never delete a run branch")
	require.Len(t, got.pushBranches, 1)
	assert.Nil(t, got.pushBranches[0],
		`the throwaway push must omit the "branch" key entirely, exactly as it always has`)
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

// ---------------------------------------------------------------------------
// listCommitLogins: maxPages bounds the walk
//
// Review feedback on the early-stop mechanism above asked for a bound: without
// one, a single requested address with no linked GitHub account — the common
// case, not an exotic one — walked a reused repo's entire branch history on
// every run. These tests pin maxPages := ceil(len(emails)/commitsPerPage) + 1:
// it actually stops the walk, reaching it is not an error, a batch bigger than
// one page still gets every page it needs, and the early stop still wins
// first when it can.
// ---------------------------------------------------------------------------

// manyFullCommitPages returns n pages of commitsPerPage entries each, none of
// which mention any address a test in this section requests — used to script
// "more branch history than the bound allows" scenarios below.
func manyFullCommitPages(n int) [][]fakeCommit {
	pages := make([][]fakeCommit, n)
	for p := 0; p < n; p++ {
		page := make([]fakeCommit, 0, commitsPerPage)
		for i := 0; i < commitsPerPage; i++ {
			page = append(page, fakeCommit{
				email: fmt.Sprintf("filler-%d-%d@example.com", p, i),
				login: fmt.Sprintf("filler-gh-%d-%d", p, i),
			})
		}
		pages[p] = page
	}
	return pages
}

// TestRevealWith_MaxPagesBoundsWalk verifies the bound actually stops the
// walk: a reused repo whose branch has far more full pages of history than
// the bound permits, and one requested email that never resolves (it never
// appears in any scripted commit), must make exactly maxPages requests — not
// walk every scripted page.
func TestRevealWith_MaxPagesBoundsWalk(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-maxpages-bound"
	emails := []string{"unresolved@example.com"}
	wantMaxPages := (len(emails)+commitsPerPage-1)/commitsPerPage + 1

	// Far more full pages of unrelated history than the bound allows, so an
	// unbounded "keep going while the page is full" loop would walk well past
	// wantMaxPages before the server ever answers with a short/empty page.
	pages := manyFullCommitPages(wantMaxPages + 3)

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      pages,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), emails, nil)
	require.NoError(t, err)

	got := rec.snapshot()
	assert.Len(t, got.commitQueries, wantMaxPages,
		"the walk must stop at maxPages rather than continuing through every scripted page")
}

// TestRevealWith_ReachingMaxPagesIsNotAnError verifies that hitting the bound
// is a normal outcome, not an error: RevealWith must return successfully with
// the unresolvable address simply absent from the map.
func TestRevealWith_ReachingMaxPagesIsNotAnError(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-maxpages-notanerror"
	const unresolved = "unresolved@example.com"
	emails := []string{unresolved}

	pages := manyFullCommitPages((len(emails)+commitsPerPage-1)/commitsPerPage + 1 + 3)

	srv, _ := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      pages,
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), emails, nil)

	require.NoError(t, err, "reaching the page bound must not surface as an error")
	assert.NotContains(t, mapping, unresolved,
		"an address GitHub never linked must simply be absent, not reported as an error")
	assert.Empty(t, mapping, "no other address was requested or could have resolved")
}

// TestRevealWith_LargeBatchGetsAllPagesWithinBound is the regression guard
// against the reviewer's originally-suggested fix, a fixed page cap: the bound
// must scale with input, not sit at a constant. A batch bigger than one page,
// whose last requested address only appears on the final page the (scaled)
// bound allows, must still resolve every single address.
func TestRevealWith_LargeBatchGetsAllPagesWithinBound(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-maxpages-largebatch"
	const batchSize = commitsPerPage + 50 // more than fits on one page

	emails := make([]string, batchSize)
	for i := range emails {
		emails[i] = fmt.Sprintf("user-%03d@example.com", i)
	}
	wantMaxPages := (len(emails)+commitsPerPage-1)/commitsPerPage + 1
	require.Equal(t, 3, wantMaxPages, "sanity: this batch size must need exactly 3 pages")

	// Page 1 resolves the first 100 requested addresses.
	page1 := make([]fakeCommit, commitsPerPage)
	for i := 0; i < commitsPerPage; i++ {
		page1[i] = fakeCommit{email: emails[i], login: fmt.Sprintf("gh-%03d", i)}
	}
	// Page 2 resolves the next batch, padded with unrelated filler to stay a
	// full page — the very last requested address is deliberately withheld.
	page2 := make([]fakeCommit, 0, commitsPerPage)
	for i := commitsPerPage; i < batchSize-1; i++ {
		page2 = append(page2, fakeCommit{email: emails[i], login: fmt.Sprintf("gh-%03d", i)})
	}
	for len(page2) < commitsPerPage {
		page2 = append(page2, fakeCommit{
			email: fmt.Sprintf("filler-%d@example.com", len(page2)),
			login: fmt.Sprintf("filler-gh-%d", len(page2)),
		})
	}
	// Page 3 — the final page the bound allows — carries only the last
	// requested address.
	last := batchSize - 1
	page3 := []fakeCommit{{email: emails[last], login: fmt.Sprintf("gh-%03d", last)}}

	srv, _ := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      [][]fakeCommit{page1, page2, page3},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), emails, nil)
	require.NoError(t, err)

	for _, email := range emails {
		assert.Contains(t, mapping, email, "every requested address in a large batch must still resolve")
	}
	assert.Len(t, mapping, batchSize)
}

// TestRevealWith_EarlyStopWinsForBatchEvenWithLargerBound verifies the early
// stop still wins when it can: when every requested address (a batch, not
// just one) resolves on page 1, exactly one commits request must be made even
// though the bound would have permitted a second page.
func TestRevealWith_EarlyStopWinsForBatchEvenWithLargerBound(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-maxpages-earlystop-batch"
	const batchSize = commitsPerPage / 2 // fits on one page with room to spare

	emails := make([]string, batchSize)
	page1 := make([]fakeCommit, 0, commitsPerPage)
	for i := range emails {
		emails[i] = fmt.Sprintf("resolved-%02d@example.com", i)
		page1 = append(page1, fakeCommit{email: emails[i], login: fmt.Sprintf("gh-%02d", i)})
	}
	// Pad page1 out to a full page and leave a page 2 present — a naive
	// "keep going while the page is full" loop would fetch it.
	for len(page1) < commitsPerPage {
		page1 = append(page1, fakeCommit{
			email: fmt.Sprintf("filler-%d@example.com", len(page1)),
			login: fmt.Sprintf("filler-gh-%d", len(page1)),
		})
	}
	page2 := []fakeCommit{{email: "should-never-be-fetched@example.com", login: "should-never-be-fetched-gh"}}

	wantMaxPages := (len(emails)+commitsPerPage-1)/commitsPerPage + 1
	require.Greater(t, wantMaxPages, 1, "sanity: the bound must permit more than one page here")

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages:      [][]fakeCommit{page1, page2},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), emails, nil)
	require.NoError(t, err)
	assert.Len(t, mapping, batchSize)

	got := rec.snapshot()
	assert.Len(t, got.commitQueries, 1,
		"the early stop must win as soon as every requested address resolves, even though the bound permits a second page")
}

// ---------------------------------------------------------------------------
// Persistent mode: the returned mapping is filtered to THIS call's emails
//
// A reused repo's commit history holds more than this call's own pushes: an
// earlier call inside the revealSinceSkew window, or a concurrent run against
// the same repo, leaves its commits on the very pages this call lists. Before
// the fix, any login found on those pages — belonging to an email the caller
// never asked about — was added to the returned mapping regardless. These
// tests pin the fix: listCommitLogins must return pairs for the REQUESTED
// emails and nothing else, named so the intent survives refactoring.
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_OmitsForeignEmailFromSameCommitPage is the direct
// reproduction of the bug all three reviewers found: a commits page holding
// both a requested email's commit and another batch's commit must yield a
// mapping containing ONLY the requested one.
func TestRevealWith_Persistent_OmitsForeignEmailFromSameCommitPage(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-foreign-email"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			{
				{email: "alice@example.com", login: "alice-gh"},     // this call's own request
				{email: "mallory@example.com", login: "mallory-gh"}, // another batch's commit
			},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"alice@example.com"}, nil)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"alice@example.com": "alice-gh"}, mapping,
		"the mapping must contain ONLY the email this call requested")
	assert.NotContains(t, mapping, "mallory@example.com",
		"a commit belonging to another batch must never leak into this call's result")

	got := rec.snapshot()
	assert.Equal(t, 1, got.pushes, "only the requested email was pushed by this call")
}

// TestRevealWith_Persistent_EmptyEmailsReturnsEmptyMapping is the "empty batch
// returns a prior batch's results" case named in review: calling RevealWith
// with no emails at all must return an EMPTY mapping even though the reused
// repo's commit page — left behind by an earlier, unrelated call — has real,
// resolvable commits sitting right there for the taking.
func TestRevealWith_Persistent_EmptyEmailsReturnsEmptyMapping(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-empty-batch"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			// Left behind by some earlier, unrelated call against this repo.
			{{email: "priorbatch@example.com", login: "priorbatch-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{}, nil)
	require.NoError(t, err)
	assert.Empty(t, mapping,
		"an empty request must never return another batch's commits just because they were on the page")

	got := rec.snapshot()
	assert.Zero(t, got.pushes, "an empty batch pushes nothing")
}

// TestRevealWith_Persistent_DuplicateRequestedEmailStillResolves verifies that
// an email appearing twice in the caller's slice does not break the
// len(mapping) == len(requested) paging-stop condition: requested is built
// from a set, so the duplicate collapses to one entry and the call must still
// resolve normally and stop paging once that one entry is found.
func TestRevealWith_Persistent_DuplicateRequestedEmailStillResolves(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-duplicate-email"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitPages: [][]fakeCommit{
			{{email: "kim@example.com", login: "kim-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"kim@example.com", "kim@example.com"}, nil)
	require.NoError(t, err, "a duplicate requested email must not break resolution")
	assert.Equal(t, map[string]string{"kim@example.com": "kim-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, 2, got.pushes, "one commit is still pushed per slice entry, duplicate included")
	assert.Len(t, got.commitQueries, 1,
		"the duplicate must not prevent the early paging stop once the single distinct email resolves")
}

// ---------------------------------------------------------------------------
// Persistent mode: the run-branch model
//
// The reused-repo redesign gives every RevealWith call its OWN branch,
// created off the repo's base commit and deleted when the call ends. That
// one decision is what replaced ?since=: another run's commits are never on
// the page a call lists, because they were never pushed to its branch. These
// tests exercise that lifecycle directly — creation, scoping of pushes and
// the commit listing, cleanup (including on failure), and the bounded name-
// collision retry.
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_RunBranchLifecycle is the steady-state case: an
// existing private repo that already has a base commit. Reveal must create
// exactly one run branch off that base SHA, push every commit onto it, list
// commits scoped to it, and delete it before returning.
func TestRevealWith_Persistent_RunBranchLifecycle(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-lifecycle"
	const baseSHA = "basecommitsha0001"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		repoReadBranch:   "main",
		refSHAStatuses:   []int{http.StatusOK}, // the repo already has a base commit
		refSHA:           baseSHA,
		commitPages: [][]fakeCommit{
			{{email: "nina@example.com", login: "nina-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"nina@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"nina@example.com": "nina-gh"}, mapping)

	got := rec.snapshot()

	require.Len(t, got.refReads, 1, "the base commit is read once, off the repo's default branch")
	assert.Equal(t, "main", got.refReads[0])

	require.Len(t, got.refCreates, 1, "exactly one run branch is created for this call")
	assert.Equal(t, "refs/heads/test-repo-name", got.refCreates[0].ref)
	assert.Equal(t, baseSHA, got.refCreates[0].sha,
		"the run branch must be created off the repo's base commit")

	require.Len(t, got.pushBranches, 1)
	require.NotNil(t, got.pushBranches[0])
	assert.Equal(t, "test-repo-name", *got.pushBranches[0],
		"every push must carry this call's own run branch")

	require.Len(t, got.commitQueries, 1)
	assert.Equal(t, "test-repo-name", got.commitQueries[0].Get("sha"),
		"the commit listing must be scoped to this call's run branch")

	assert.Equal(t, []string{"test-repo-name"}, got.refDeletes,
		"the run branch must be deleted before RevealWith returns")
}

// TestRevealWith_Persistent_RunBranchDeletedDespiteLaterFailure verifies the
// run branch's cleanup runs even when a LATER step (the commit listing)
// fails — the same guarantee the throwaway repo delete has always made,
// carried over to the run-branch delete.
func TestRevealWith_Persistent_RunBranchDeletedDespiteLaterFailure(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-cleanup-on-failure"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		commitsStatus:    http.StatusInternalServerError, // the listing fails after the pushes succeed
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"oscar@example.com"}, nil)
	require.Error(t, err, "a failed commit listing must surface as an error")
	assert.Contains(t, err.Error(), "500")

	got := rec.snapshot()
	assert.Equal(t, []string{"test-repo-name"}, got.refDeletes,
		"the run branch must still be deleted even though a later step failed")
}

// TestRevealWith_Persistent_RunBranchDeleteFailureSurfaces verifies that a
// failed run-branch DELETE is not silently swallowed: RevealWith's error must
// name the branch (mirroring the throwaway repo delete-failure contract), and
// the mapping already resolved must still be returned rather than discarded.
func TestRevealWith_Persistent_RunBranchDeleteFailureSurfaces(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-delete-failure"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses:  []int{http.StatusOK},
		refDeleteStatuses: []int{http.StatusInternalServerError},
		commitPages: [][]fakeCommit{
			{{email: "paula@example.com", login: "paula-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"paula@example.com"}, nil)
	require.Error(t, err, "a failed run-branch DELETE must surface as an error")
	assert.Contains(t, err.Error(), "test-repo-name",
		"the error must name the branch so the operator can delete it manually")
	assert.Equal(t, map[string]string{"paula@example.com": "paula-gh"}, mapping,
		"the resolved mapping must still be returned even when the branch delete fails")

	got := rec.snapshot()
	assert.Len(t, got.refDeletes, 1, "the delete was still attempted")
}

// TestRevealWith_Persistent_RunBranchDeleteFailureJoinedWithOriginalError
// mirrors TestReveal_MidFlowErrorAndDeleteFailure_OriginalErrorJoined for the
// throwaway repo delete: when RevealWith has ALREADY failed (the commit
// listing errors) AND the run-branch DELETE also fails, the returned error
// must reference the original failure rather than being replaced by the
// delete failure.
func TestRevealWith_Persistent_RunBranchDeleteFailureJoinedWithOriginalError(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-dual-failure"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses:  []int{http.StatusOK},
		commitsStatus:     http.StatusInternalServerError,
		refDeleteStatuses: []int{http.StatusInternalServerError},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	_, err := e.RevealWith(context.Background(), []string{"quinn@example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500",
		"the original commit-listing failure must still be present")
	assert.Contains(t, err.Error(), "test-repo-name",
		"the delete failure must ALSO be present, joined onto the original rather than replacing it")

	got := rec.snapshot()
	assert.Len(t, got.refDeletes, 1)
}

// TestRevealWith_Persistent_RunBranchNameCollisionRetries verifies that a 422
// "ref already exists" on the run-branch create is retried with a fresh name
// (via e.newName()) rather than failing outright, succeeding once a name is
// available.
func TestRevealWith_Persistent_RunBranchNameCollisionRetries(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-collision-retry"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses:  []int{http.StatusOK},
		refCreateStatuses: []int{http.StatusUnprocessableEntity, http.StatusCreated},
		commitPages: [][]fakeCommit{
			{{email: "ruth@example.com", login: "ruth-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")
	e.newName = counterName()

	mapping, err := e.RevealWith(context.Background(), []string{"ruth@example.com"}, nil)
	require.NoError(t, err, "a 422 collision followed by a 201 must not surface as an error")
	assert.Equal(t, map[string]string{"ruth@example.com": "ruth-gh"}, mapping)

	got := rec.snapshot()
	require.Len(t, got.refCreates, 2, "the rejected attempt plus the retry that succeeded")
	assert.NotEqual(t, got.refCreates[0].ref, got.refCreates[1].ref,
		"the retry must use a fresh name (via e.newName()), not replay the rejected one")
}

// TestRevealWith_Persistent_RunBranchNameCollisionExhausted verifies the
// bound: when every run-branch create attempt collides with 422, RevealWith
// fails after exactly maxRunBranchAttempts retries on top of the initial
// attempt, rather than looping forever.
func TestRevealWith_Persistent_RunBranchNameCollisionExhausted(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-run-branch-collision-exhausted"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses:  []int{http.StatusOK},
		refCreateStatuses: []int{http.StatusUnprocessableEntity}, // every attempt collides
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")
	e.newName = counterName()

	_, err := e.RevealWith(context.Background(), []string{"sam@example.com"}, nil)
	require.Error(t, err, "an exhausted name-collision budget must surface as an error")
	assert.Contains(t, err.Error(), "422")

	got := rec.snapshot()
	assert.Len(t, got.refCreates, maxRunBranchAttempts+1,
		"bounded: the initial attempt plus exactly maxRunBranchAttempts retries, no infinite loop")
	assert.Zero(t, got.pushes, "no commits may be pushed once the run branch could not be created")
}

// ---------------------------------------------------------------------------
// Persistent mode: base commit initialization
//
// A newly created reveal repo is empty, and an empty repo has no commit to
// branch the run branch from. ensureBaseCommit initializes it on the first
// call, and every later call reuses that one commit as the base. These tests
// exercise that path directly.
// ---------------------------------------------------------------------------

// TestRevealWith_Persistent_InitializesEmptyRepoOn404 covers the ref-read
// answer for a genuinely empty repo (no branch yet): one init commit is
// pushed to the default branch with NO branch key, the ref is re-read, and
// that commit becomes the base for the run branch. The init commit's own
// author (baseInitEmail) must never leak into the returned mapping even when
// the commit listing includes it.
func TestRevealWith_Persistent_InitializesEmptyRepoOn404(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-init-404"
	const baseSHA = "freshbasecommitsha"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		repoReadBranch:   "main",
		refSHAStatuses:   []int{http.StatusNotFound, http.StatusOK},
		refSHA:           baseSHA,
		commitPages: [][]fakeCommit{
			{
				{email: baseInitEmail, login: "owner-gh"}, // the init commit's own author
				{email: "tara@example.com", login: "tara-gh"},
			},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"tara@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"tara@example.com": "tara-gh"}, mapping,
		"the init commit's own author must never appear in the returned mapping")

	got := rec.snapshot()
	assert.Equal(t, []string{"main", "main"}, got.refReads,
		"the empty check, then the re-read after initializing")

	require.Len(t, got.pushBranches, 2, "the init commit plus the one requested email")
	assert.Nil(t, got.pushBranches[0],
		"the init commit must be pushed with no branch key, onto the repo's default branch")
	require.NotNil(t, got.pushBranches[1])
	assert.Equal(t, "test-repo-name", *got.pushBranches[1],
		"the requested email's commit must land on the run branch")

	require.Len(t, got.refCreates, 1)
	assert.Equal(t, baseSHA, got.refCreates[0].sha,
		"the run branch must be created off the freshly-initialized base commit")
}

// TestRevealWith_Persistent_InitializesEmptyRepoOn409 covers GitHub's OTHER
// answer for a repository with no commits at all: HTTP 409 on the ref read.
// ensureBaseCommit must treat it exactly like 404, not as an error.
func TestRevealWith_Persistent_InitializesEmptyRepoOn409(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-init-409"
	const baseSHA = "freshbasecommitsha409"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		refSHAStatuses:   []int{http.StatusConflict, http.StatusOK},
		refSHA:           baseSHA,
		commitPages: [][]fakeCommit{
			{{email: "uma@example.com", login: "uma-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"uma@example.com"}, nil)
	require.NoError(t, err, "a 409 ref read must NOT be treated as an error")
	assert.Equal(t, map[string]string{"uma@example.com": "uma-gh"}, mapping)

	got := rec.snapshot()
	require.Len(t, got.pushBranches, 2, "the init commit plus the one requested email")
	assert.Nil(t, got.pushBranches[0], "the init commit must be pushed with no branch key")

	require.Len(t, got.refCreates, 1)
	assert.Equal(t, baseSHA, got.refCreates[0].sha)
}

// TestRevealWith_Persistent_ExistingBaseCommitNotReinitialized verifies a repo
// that already has a base commit is read once and never re-initialized: no
// init push occurs, and the ref is read exactly once.
func TestRevealWith_Persistent_ExistingBaseCommitNotReinitialized(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-no-reinit"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		refSHAStatuses:   []int{http.StatusOK}, // already initialized
		commitPages: [][]fakeCommit{
			{{email: "victor@example.com", login: "victor-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"victor@example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"victor@example.com": "victor-gh"}, mapping)

	got := rec.snapshot()
	assert.Len(t, got.refReads, 1, "an already-initialized repo is read exactly once, never re-checked")
	assert.Len(t, got.pushBranches, 1, "only the requested email is pushed — no init commit")
}

// TestRevealWith_Persistent_InitRaceUsesOtherRunsBase covers the race two
// concurrent first-callers can hit: this call's own init push fails, but a
// re-read of the ref then succeeds — meaning some OTHER run won the race and
// its commit is a perfectly good base. RevealWith must use that commit rather
// than failing.
func TestRevealWith_Persistent_InitRaceUsesOtherRunsBase(t *testing.T) {
	t.Parallel()

	const token = "ghp-persistent-init-race"
	const raceWinnerSHA = "otherrunsbasecommit"

	srv, rec := newRevealServer(t, token, &revealServerOpts{
		repoReadStatuses: []int{http.StatusOK},
		refSHAStatuses:   []int{http.StatusNotFound, http.StatusOK}, // empty, then found (the other run's commit)
		refSHA:           raceWinnerSHA,
		pushStatuses:     []int{http.StatusInternalServerError, http.StatusCreated}, // this run's own init push fails; the email push succeeds
		commitPages: [][]fakeCommit{
			{{email: "wendy@example.com", login: "wendy-gh"}},
		},
	})
	e := newPersistentEnumerator(t, srv, token, "guard-osint-reveal")

	mapping, err := e.RevealWith(context.Background(), []string{"wendy@example.com"}, nil)
	require.NoError(t, err, "a failed init push must not fail the call when the ref re-read finds a base")
	assert.Equal(t, map[string]string{"wendy@example.com": "wendy-gh"}, mapping)

	got := rec.snapshot()
	assert.Equal(t, 2, got.pushes, "the failed init attempt plus the one successful email push")
	require.Len(t, got.refCreates, 1)
	assert.Equal(t, raceWinnerSHA, got.refCreates[0].sha,
		"the run branch must be created off the OTHER run's base commit, not this run's failed attempt")
}
