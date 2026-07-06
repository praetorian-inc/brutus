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
	"net/http"
	"net/url"

	"github.com/praetorian-inc/brutus/pkg/enum"
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

	var repo, branch string
	repo, branch, err = e.createRepo(ctx)
	if err != nil {
		return nil, err
	}

	// ALWAYS delete the repo, even if a later step fails. RevealWith uses NAMED
	// returns so this deferred reassignment of err actually propagates to the
	// caller — with unnamed returns the `return mapping, err` value is captured
	// before the defer runs and a delete failure would be silently lost
	// (orphaning a private repo under the operator's account). On delete failure
	// the returned error carries the full owner/repo so the operator can remove
	// it manually; if the function already failed, the original error is joined
	// (not overwritten). The token is never included in the error.
	defer func() {
		if delErr := e.deleteRepo(ctx, login, repo); delErr != nil {
			repoURL := login + "/" + repo
			if err != nil {
				err = fmt.Errorf("%w; ADDITIONALLY failed to delete temp repo %q (delete it manually): %v", err, repoURL, delErr)
			} else {
				err = fmt.Errorf("github reveal: failed to delete temp repo %q (delete it manually): %v", repoURL, delErr)
			}
		}
	}()

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

	mapping, err = e.listCommitLogins(ctx, login, repo, branch)
	if err != nil {
		return nil, err
	}
	return mapping, nil
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

// pushCommit PUTs a new file to {api}/repos/{owner}/{repo}/contents/{file} with
// the target email set as both author and committer, so GitHub attributes the
// commit to that email. HTTP 429 is retried (bounded). Commits are pushed
// sequentially by the caller (single branch).
func (e *Enumerator) pushCommit(ctx context.Context, owner, repo, email string) error {
	for attempt := 0; ; attempt++ {
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
			if attempt >= maxRateLimitRetries {
				return fmt.Errorf("github reveal: pushing commit rate limited (HTTP 429) after %d retries", attempt)
			}
			if err := e.sleep(ctx, rateLimitBackoff); err != nil {
				return err
			}
			continue
		default:
			return fmt.Errorf("github reveal: pushing commit returned HTTP %d", status)
		}
	}
}

// listCommitLogins paginates {api}/repos/{owner}/{repo}/commits?sha={branch} and
// returns a map of commit author email -> account login. Commits whose top-level
// author (the linked GitHub account) is absent/null are omitted (no linked
// account for that email).
func (e *Enumerator) listCommitLogins(ctx context.Context, owner, repo, branch string) (map[string]string, error) {
	mapping := make(map[string]string)

	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/%s/commits?sha=%s&per_page=100&page=%d",
			owner, repo, url.QueryEscape(branch), page)

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
			if email == "" {
				continue
			}
			mapping[email] = commits[i].Author.Login
		}

		if len(commits) < 100 {
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
