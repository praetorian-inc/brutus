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
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// cleanupTimeout bounds the deferred throwaway-repo deletion in RevealWith. The
// deletion runs on a context detached from the reveal ctx (which may already be
// canceled or past its deadline), so it needs its own deadline to guarantee it
// cannot hang.
const cleanupTimeout = 30 * time.Second

const (
	// revealSinceSkew is how far before the push loop the commit-listing floor
	// (?since=) is placed in persistent-repo mode. That filter is applied
	// SERVER-SIDE, against GitHub's clock rather than ours, so the floor is
	// nudged into the past to tolerate clock drift between the two; without the
	// allowance a host running slightly ahead of GitHub would filter out the
	// very commits it had just pushed. Keep it small — everything inside the
	// window is history from earlier calls that this call will also see.
	revealSinceSkew = time.Minute

	// repoNameMaxLen is GitHub's maximum repository-name length.
	repoNameMaxLen = 100

	// commitsPerPage is the page size requested from the commits endpoint; a
	// short page means the last page has been reached.
	commitsPerPage = 100
)

// ---------------------------------------------------------------------------
// Username reveal (authenticated)
// ---------------------------------------------------------------------------

// Reveal resolves GitHub usernames for the given (existing) emails. It is a
// thin wrapper over RevealWith with no progress callback, preserving the
// original signature for existing callers and tests.
func (e *Enumerator) Reveal(ctx context.Context, emails []string) (mapping map[string]string, err error) {
	return e.RevealWith(ctx, emails, nil)
}

// RevealWith resolves GitHub usernames for the given (existing) emails. It
// requires a non-empty token. A throwaway private repo is created, one commit
// per email is pushed with that email as author/committer, the commits are
// listed after a settle delay, and email -> login pairs are collected. The repo
// is ALWAYS deleted before returning (even on mid-flow error). If deletion
// fails, the returned error is annotated with the full owner/repo so the
// operator can remove it manually. The token is never logged.
//
// When SetRevealRepo has been called, the named private repo is REUSED instead
// (created only if absent) and is never deleted; the commit listing is then
// bounded to this call with ?since=. See SetRevealRepo.
//
// onProgress, when non-nil, is invoked after each successful commit push with
// (done, total) where done is 1-based and total is len(emails). The push loop
// is the long, blind phase of reveal, so this lets callers render live
// progress. It is never called for the settle delay or the commit listing.
//
// Logins are omitted from the map when GitHub did not link an account to the
// commit author email (author absent/null).
func (e *Enumerator) RevealWith(ctx context.Context, emails []string, onProgress func(done, total int)) (mapping map[string]string, err error) {
	if e.token == "" {
		return nil, fmt.Errorf("github reveal: token required (set GITHUB_TOKEN or --token)")
	}

	var login string
	login, err = e.getAuthUser(ctx)
	if err != nil {
		return nil, err
	}

	// persistent reports whether the caller opted into reusing a named repo
	// (SetRevealRepo) instead of the default create-then-delete throwaway.
	persistent := e.revealRepo != ""

	var repo, branch string
	if persistent {
		repo, branch, err = e.resolveRevealRepo(ctx, login)
	} else {
		repo, branch, err = e.createRepo(ctx)
	}
	if err != nil {
		return nil, err
	}

	if !persistent {
		// ALWAYS delete the repo, even if a later step fails. RevealWith uses NAMED
		// returns so this deferred reassignment of err actually propagates to the
		// caller — with unnamed returns the `return mapping, err` value is captured
		// before the defer runs and a delete failure would be silently lost
		// (orphaning a private repo under the operator's account). On delete failure
		// the returned error carries the full owner/repo so the operator can remove
		// it manually; if the function already failed, the original error is joined
		// (not overwritten). The token is never included in the error.
		//
		// Registered only in throwaway mode: a persistent repo is the caller's
		// long-lived, reused repo, so deleting it would defeat the entire point
		// of the mode (and is why persistent mode needs no delete_repo scope).
		defer func() {
			// Detach cleanup from ctx's cancellation/deadline: reveal's ctx may
			// already be canceled or timed out (e.g. a caller deadline, or the
			// settle-delay sleep returning early), and reusing it here would make
			// the DELETE fail to send and orphan the throwaway private repo under
			// the operator's account. context.WithoutCancel keeps ctx's values
			// while dropping cancellation; a fresh short timeout bounds the delete.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			defer cancel()
			if delErr := e.deleteRepo(cleanupCtx, login, repo); delErr != nil {
				repoURL := login + "/" + repo
				if err != nil {
					err = fmt.Errorf("%w; ADDITIONALLY failed to delete temp repo %q (delete it manually): %v", err, repoURL, delErr)
				} else {
					err = fmt.Errorf("github reveal: failed to delete temp repo %q (delete it manually): %v", repoURL, delErr)
				}
			}
		}()
	}

	// since is the floor for the commit listing below, captured BEFORE the push
	// loop so every commit this call is about to push falls inside the window.
	// Without it a reused repo would be re-walked from the beginning on every
	// call — after a 3,000-person roster that is 30+ pages, growing without
	// limit, and it would report logins for emails the caller never asked about.
	//
	// Only persistent mode needs it. A throwaway repo is created empty, so it
	// holds no history to exclude, and sending `since` there would add pure
	// clock-skew risk to a path whose behavior must not change. The zero value
	// means "send no since parameter".
	var since time.Time
	if persistent {
		since = time.Now().Add(-revealSinceSkew)
	}

	for i, email := range emails {
		if perr := e.pushCommit(ctx, login, repo, email); perr != nil {
			return nil, perr
		}
		if onProgress != nil {
			onProgress(i+1, len(emails))
		}
	}

	if serr := e.sleep(ctx, e.settleDelay); serr != nil {
		return nil, serr
	}

	mapping, err = e.listCommitLogins(ctx, login, repo, branch, since, emails)
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

// SetRevealRepo opts RevealWith into persistent-repo mode: rather than creating
// a throwaway private repo per call and deleting it afterwards, reveal REUSES
// the private repo called name under the authenticated account, creating it only
// when absent and never deleting it.
//
// The default flow costs one repo create AND one repo delete per call, so
// resolving a roster one person at a time drives thousands of create/delete
// pairs through a single PAT — precisely the pattern GitHub's per-token
// secondary rate limits and abuse detection react to. Reusing one repo removes
// nearly all of that churn; because nothing is deleted, the PAT no longer needs
// the delete_repo scope and the orphaned-private-repo failure mode disappears.
//
// name is validated here, so an invalid name is rejected before any HTTP request
// is issued; on error the enumerator is left in its previous mode. Note that a
// reused repo accumulates one file and one commit per email forever — the commit
// LISTING stays bounded (see revealSinceSkew), but the repo itself grows, so it
// is the operator's to prune.
func (e *Enumerator) SetRevealRepo(name string) error {
	if err := validateRepoName(name); err != nil {
		return err
	}
	e.revealRepo = name
	return nil
}

// ---------------------------------------------------------------------------
// Reveal helpers
// ---------------------------------------------------------------------------

// getAuthUser GETs {api}/user and returns the authenticated account's login.
func (e *Enumerator) getAuthUser(ctx context.Context) (string, error) {
	resp, err := e.apiRequest(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github reveal: GET /user returned HTTP %d", resp.StatusCode)
	}

	// Bounded read — reuses enum.ReadResponseBody (1 MB default) before unmarshal.
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return "", fmt.Errorf("github reveal: reading /user: %w", err)
	}

	var user struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("github reveal: decoding /user: %w", err)
	}
	if user.Login == "" {
		return "", fmt.Errorf("github reveal: /user returned an empty login")
	}
	return user.Login, nil
}

// createRepo POSTs {api}/user/repos to create a private throwaway repo, returning
// its name and default branch (falling back to "main" when absent).
func (e *Enumerator) createRepo(ctx context.Context) (repo, branch string, err error) {
	name := e.newName()
	payload := map[string]any{"name": name, "private": true}

	resp, err := e.apiRequest(ctx, http.MethodPost, "/user/repos", payload)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("github reveal: creating repo returned HTTP %d", resp.StatusCode)
	}

	// Bounded read — reuses enum.ReadResponseBody (1 MB default) before unmarshal.
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return "", "", fmt.Errorf("github reveal: reading repo creation: %w", err)
	}

	var created struct {
		Name          string `json:"name"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return "", "", fmt.Errorf("github reveal: decoding repo creation: %w", err)
	}
	if created.Name == "" {
		created.Name = name
	}
	if created.DefaultBranch == "" {
		created.DefaultBranch = defaultBranchDefault
	}
	return created.Name, created.DefaultBranch, nil
}

// validateRepoName enforces GitHub's repository-name rules: 1..100 characters
// drawn from letters, digits, "-", "_" and ".". It additionally rejects the
// pure-dot names "." and "..", which satisfy a naive character check but are
// path segments rather than repositories — and the name is interpolated into API
// URL paths.
func validateRepoName(name string) error {
	if name == "" {
		return fmt.Errorf("github reveal: repo name must not be empty")
	}
	if len(name) > repoNameMaxLen {
		return fmt.Errorf("github reveal: repo name %q exceeds the %d-character limit", name, repoNameMaxLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("github reveal: repo name %q is a path segment, not a repository name", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("github reveal: repo name %q contains invalid character %q (allowed: letters, digits, %q, %q, %q)",
				name, r, "-", "_", ".")
		}
	}
	return nil
}

// resolveRevealRepo returns the persistent reveal repo's name and default
// branch, creating the repo only when it is absent.
//
// A repo that already exists is REFUSED unless GitHub confirms it is private.
// Reveal writes every target email into commit metadata, so reusing a public
// repo under the caller's name would publish the whole target list. Creation
// always sets private:true, so only the reuse paths need the check.
//
// It READS before creating (GET /repos/{owner}/{name}) rather than
// creating-then-tolerating-422. In the steady state the repo already exists, so
// the read is a single request that also yields the default branch, whereas
// create-first would spend a POST that 422s *plus* a follow-up GET for the
// branch on every single call — more traffic against the very PAT this mode
// exists to protect, and it would need the 422 body parsed on the hot path
// instead of the rare one. The create branch still tolerates HTTP 422 "already
// exists" to cover the race where the repo appears between our read and our
// write.
func (e *Enumerator) resolveRevealRepo(ctx context.Context, owner string) (repo, branch string, err error) {
	name := e.revealRepo

	info, found, err := e.getRepo(ctx, owner, name)
	if err != nil {
		return "", "", err
	}

	if !found {
		var existed bool
		branch, existed, err = e.createNamedRepo(ctx, name)
		if err != nil {
			return "", "", err
		}
		if !existed {
			// We created it ourselves with private:true, so no check is needed.
			return name, branch, nil
		}

		// Raced: something created the repo between our read and our create, so
		// the create response carried no branch. Re-read to learn it — and to
		// learn its visibility, since a repo we did not create is not one we can
		// assume anything about.
		info, found, err = e.getRepo(ctx, owner, name)
		if err != nil {
			return "", "", err
		}
		if !found {
			return "", "", fmt.Errorf("github reveal: repo %q already exists but could not be read", owner+"/"+name)
		}
	}

	// Both paths that reach here reuse a repo somebody else created.
	if !info.private {
		return "", "", fmt.Errorf(
			"github reveal: refusing to reuse %q because it is public — reveal writes every target email into commit metadata, so the reveal repo must be private",
			owner+"/"+name)
	}
	return name, info.branch, nil
}

// repoInfo is what the reuse path needs to know about an existing repo: which
// branch to list commits from, and whether it is private. Visibility travels
// with the branch rather than being fetched separately so the two can never be
// read from different responses.
type repoInfo struct {
	branch  string
	private bool
}

// getRepo GETs {api}/repos/{owner}/{repo} and returns that repo's default branch
// (falling back to "main" when absent) together with its visibility. found is
// false, with no error, when GitHub answers HTTP 404 — the repo simply is not
// there yet.
func (e *Enumerator) getRepo(ctx context.Context, owner, repo string) (info repoInfo, found bool, err error) {
	resp, err := e.apiRequest(ctx, http.MethodGet, "/repos/"+owner+"/"+repo, nil)
	if err != nil {
		return repoInfo{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return repoInfo{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return repoInfo{}, false, fmt.Errorf("github reveal: reading repo returned HTTP %d", resp.StatusCode)
	}

	// Bounded read — reuses enum.ReadResponseBody (1 MB default) before unmarshal.
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return repoInfo{}, false, fmt.Errorf("github reveal: reading repo: %w", err)
	}

	var existing struct {
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
	}
	if err := json.Unmarshal(body, &existing); err != nil {
		return repoInfo{}, false, fmt.Errorf("github reveal: decoding repo: %w", err)
	}
	if existing.DefaultBranch == "" {
		existing.DefaultBranch = defaultBranchDefault
	}
	// A response that omits "private" decodes to false and is therefore refused
	// by the caller. That is the safe direction: reveal publishes email
	// addresses, so "could not confirm private" must not read as "is private".
	return repoInfo{branch: existing.DefaultBranch, private: existing.Private}, true, nil
}

// createNamedRepo POSTs {api}/user/repos to create a private repo called name,
// returning its default branch (falling back to "main" when absent). existed is
// true when GitHub answered HTTP 422 *because the name is already taken on the
// account* — a success for persistent mode, not a failure. Any other 422 (an
// invalid name, an exhausted repository quota) is returned as an error.
//
// This deliberately does not share code with createRepo: that function backs the
// default throwaway flow, whose behavior — including its exact status handling
// and error strings — must not change, and the two differ in substance anyway
// (created-or-fail vs. created-or-already-there, random name vs. caller's name).
func (e *Enumerator) createNamedRepo(ctx context.Context, name string) (branch string, existed bool, err error) {
	payload := map[string]any{"name": name, "private": true}

	resp, err := e.apiRequest(ctx, http.MethodPost, "/user/repos", payload)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded read — reuses enum.ReadResponseBody (1 MB default) before
	// unmarshal. Read before branching on status: a 422 needs its body to tell
	// "already exists" apart from every other rejection.
	body, err := enum.ReadResponseBody(resp, 0)
	if err != nil {
		return "", false, fmt.Errorf("github reveal: reading repo creation: %w", err)
	}

	if resp.StatusCode == http.StatusUnprocessableEntity && repoNameTaken(body) {
		return "", true, nil
	}
	if resp.StatusCode != http.StatusCreated {
		return "", false, fmt.Errorf("github reveal: creating repo returned HTTP %d", resp.StatusCode)
	}

	var created struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return "", false, fmt.Errorf("github reveal: decoding repo creation: %w", err)
	}
	if created.DefaultBranch == "" {
		created.DefaultBranch = defaultBranchDefault
	}
	return created.DefaultBranch, false, nil
}

// repoNameTaken reports whether an HTTP 422 body from POST /user/repos is the
// "name already exists on this account" validation error rather than some other
// rejection (an invalid name, an exhausted repository quota). GitHub reports it
// per-field inside an errors array.
func repoNameTaken(body []byte) bool {
	var payload struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	for _, e := range payload.Errors {
		// Require the error to be about the NAME. A 422 whose "already exists"
		// message concerns some other field is a different rejection, and
		// treating it as reuse would push commits at a repo we never resolved.
		if strings.EqualFold(e.Field, "name") && strings.Contains(strings.ToLower(e.Message), "already exists") {
			return true
		}
	}
	return false
}

// pushCommit PUTs a new file to {api}/repos/{owner}/{repo}/contents/{file} with
// the target email set as both author and committer, so GitHub attributes the
// commit to that email. HTTP 429 and HTTP 409 are each retried (bounded, with
// independent budgets so one cannot consume the other's). Commits are pushed
// sequentially by the caller (single branch).
func (e *Enumerator) pushCommit(ctx context.Context, owner, repo, email string) error {
	var rateLimits, conflicts int
	for {
		file := e.newName()
		payload := map[string]any{
			"message":   "Test",
			"content":   commitContent,
			"author":    map[string]string{"name": "TestUser", "email": email},
			"committer": map[string]string{"name": "TestUser", "email": email},
		}
		path := "/repos/" + owner + "/" + repo + "/contents/" + file

		resp, err := e.apiRequest(ctx, http.MethodPut, path, payload)
		if err != nil {
			return err
		}
		status := resp.StatusCode
		_ = resp.Body.Close()

		switch status {
		case http.StatusCreated, http.StatusOK:
			return nil
		case http.StatusTooManyRequests:
			if rateLimits >= maxRateLimitRetries {
				return fmt.Errorf("github reveal: pushing commit rate limited (HTTP 429) after %d retries", rateLimits)
			}
			rateLimits++
			if err := e.sleep(ctx, rateLimitBackoff); err != nil {
				return err
			}
			continue
		case http.StatusConflict:
			// Another writer advanced this branch between GitHub reading its head
			// and applying our commit. Only a REUSED repo (SetRevealRepo) can see
			// this: a throwaway repo belongs to the single call that created it.
			// The retry loops back through e.newName(), so it pushes a fresh file
			// rather than replaying a rejected write, and the email is still
			// committed exactly once on success.
			if conflicts >= maxConflictRetries {
				return fmt.Errorf("github reveal: pushing commit conflicted (HTTP 409) after %d retries", conflicts)
			}
			conflicts++
			if err := e.sleep(ctx, conflictBackoff(conflicts)); err != nil {
				return err
			}
			continue
		default:
			return fmt.Errorf("github reveal: pushing commit returned HTTP %d", status)
		}
	}
}

// conflictBackoff returns how long to wait before retrying a push that lost a
// branch-head race, growing with each attempt and carrying up to 50% jitter.
// The jitter is the point: two runs contending over one reused repo that both
// waited exactly conflictBackoffBase would simply collide a second time. attempt
// is 1-based.
func conflictBackoff(attempt int) time.Duration {
	base := conflictBackoffBase * time.Duration(attempt)
	return base + rand.N(base/2+1)
}

// listCommitLogins paginates {api}/repos/{owner}/{repo}/commits?sha={branch} and
// returns a map of commit author email -> account login. Commits whose top-level
// author (the linked GitHub account) is absent/null are omitted (no linked
// account for that email).
//
// since, when non-zero, is sent as ?since= to floor the listing at this call's
// own commits — required for a reused repo, whose history would otherwise be
// re-walked in full on every call. The filter is evaluated SERVER-SIDE against
// GitHub's clock (see revealSinceSkew), so a zero since sends no parameter at all
// and leaves the query exactly as the throwaway-repo flow has always sent it.
//
// emails is the set the caller asked about: it both FILTERS the returned pairs
// and bounds paging (see requested below).
func (e *Enumerator) listCommitLogins(ctx context.Context, owner, repo, branch string, since time.Time, emails []string) (map[string]string, error) {
	mapping := make(map[string]string)

	// requested is the set of addresses this call asked about, and pairs are
	// added ONLY for emails in it.
	//
	// The listing is floored by ?since= but is not restricted to our commits: a
	// reused repo carries other runs' commits, both from earlier calls inside
	// the skew window and from runs happening right now. Returning those would
	// break RevealWith's contract — the caller would receive logins for
	// addresses it never submitted, and an empty batch could come back holding
	// another batch's results. Filtering is what keeps the returned map a
	// function of the caller's own input.
	//
	// It doubles as the paging bound: commits come back newest-first, so a
	// call's own commits sit on the early pages and there is nothing further to
	// learn once every requested address has a login.
	requested := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		if email != "" {
			requested[email] = struct{}{}
		}
	}

	sinceParam := ""
	if !since.IsZero() {
		sinceParam = "&since=" + url.QueryEscape(since.UTC().Format(time.RFC3339))
	}

	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/%s/commits?sha=%s&per_page=%d&page=%d%s",
			owner, repo, url.QueryEscape(branch), commitsPerPage, page, sinceParam)

		resp, err := e.apiRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("github reveal: listing commits returned HTTP %d", resp.StatusCode)
		}

		// Bounded read — reuses enum.ReadResponseBody (1 MB default) before
		// unmarshal so a hostile API response cannot exhaust memory.
		body, readErr := enum.ReadResponseBody(resp, 0)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("github reveal: reading commits: %w", readErr)
		}

		var commits []struct {
			Commit struct {
				Author struct {
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
		}
		if decodeErr := json.Unmarshal(body, &commits); decodeErr != nil {
			return nil, fmt.Errorf("github reveal: decoding commits: %w", decodeErr)
		}

		for i := range commits {
			email := commits[i].Commit.Author.Email
			// author is null when the email isn't linked to a GitHub account.
			if commits[i].Author == nil || commits[i].Author.Login == "" {
				continue
			}
			// Another run's commit, or one of ours from an earlier call: it is
			// not part of what this caller asked for, so it is not ours to
			// report. This also drops the empty-email case for free.
			if _, ok := requested[email]; !ok {
				continue
			}
			mapping[email] = commits[i].Author.Login
		}

		// mapping's keys are a subset of requested, so equal sizes mean every
		// requested address resolved and later pages cannot add anything.
		if len(mapping) == len(requested) {
			break
		}

		if len(commits) < commitsPerPage {
			break
		}
	}

	return mapping, nil
}

// deleteRepo DELETEs {api}/repos/{owner}/{repo}. A 404 is treated as success
// (already gone). This is invoked from Reveal's deferred cleanup.
func (e *Enumerator) deleteRepo(ctx context.Context, owner, repo string) error {
	resp, err := e.apiRequest(ctx, http.MethodDelete, "/repos/"+owner+"/"+repo, nil)
	if err != nil {
		return err
	}
	status := resp.StatusCode
	_ = resp.Body.Close()

	if status == http.StatusNoContent || status == http.StatusOK || status == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("DELETE returned HTTP %d", status)
}

// apiRequest issues an authenticated GitHub REST API request. payload, when
// non-nil, is JSON-encoded as the request body. The Authorization header carries
// the bearer token (never logged) and Accept requests the v3 media type.
func (e *Enumerator) apiRequest(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("github reveal: encoding request body: %w", err)
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, e.apiBaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("github reveal: creating %s %s request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Use apiClient (no-follow): this request carries the PAT, so redirects must
	// not be followed to avoid leaking the token across hosts (PAT-leak
	// protection). The existence flow uses httpClient, which follows redirects.
	resp, err := e.apiClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github reveal: %s %s failed: %w", method, path, err)
	}
	return resp, nil
}
