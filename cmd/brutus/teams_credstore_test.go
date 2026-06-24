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

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// ---------------------------------------------------------------------------
// teamsDefaultTokenPath
// ---------------------------------------------------------------------------

// TestTeamsDefaultTokenPath verifies that teamsDefaultTokenPath returns a path
// ending with ".brutus/teams.json" rooted under the current home directory.
// We redirect $HOME to a temp dir so the real ~/.brutus is never touched.
func TestTeamsDefaultTokenPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := teamsDefaultTokenPath()
	require.NoError(t, err)

	// Must be an absolute path beneath the temp home dir.
	assert.True(t, filepath.IsAbs(got), "path must be absolute, got %q", got)
	assert.True(t, strings.HasPrefix(got, home),
		"path must be under temp home %q, got %q", home, got)

	// Must end with the expected relative segment.
	assert.True(t, strings.HasSuffix(got, filepath.Join(".brutus", "teams.json")),
		`path must end with ".brutus/teams.json", got %q`, got)
}

// ---------------------------------------------------------------------------
// saveTeamsTokenFile — permissions and content
// ---------------------------------------------------------------------------

// TestSaveTeamsTokenFile_PermsAndContent saves a well-known TokenSet and then
// asserts:
//   - the file exists with mode 0600
//   - a directory created by saveTeamsTokenFile has mode 0700
//   - the JSON content contains type=="teams_token", access_token=="AAA",
//     refresh_token=="RRR"
//
// To test that saveTeamsTokenFile creates the parent dir with 0700 (not just
// that any existing parent is 0700), we point at a subdirectory that does not
// exist yet, so saveTeamsTokenFile is the one that creates it.
func TestSaveTeamsTokenFile_PermsAndContent(t *testing.T) {
	base := t.TempDir()
	// "subdir" does not exist yet — saveTeamsTokenFile must create it.
	subdir := filepath.Join(base, "subdir")
	path := filepath.Join(subdir, "teams.json")

	tok := &teams.TokenSet{
		AccessToken:  "AAA",
		RefreshToken: "RRR",
		IDToken:      "III",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "offline_access https://api.spaces.skype.com/.default",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}

	err := saveTeamsTokenFile(path, tok)
	require.NoError(t, err, "saveTeamsTokenFile must not return an error")

	// --- File must exist ---
	fi, err := os.Stat(path)
	require.NoError(t, err, "token file must exist after saveTeamsTokenFile")

	// --- File permissions must be 0600 ---
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(),
		"token file must have mode 0600 to protect sensitive credentials")

	// --- Directory created by saveTeamsTokenFile must have mode 0700 ---
	di, err := os.Stat(subdir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm(),
		"directory created by saveTeamsTokenFile must have mode 0700")

	// --- JSON content must decode correctly ---
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &obj),
		"token file must contain valid JSON")

	assert.Equal(t, "teams_token", obj["type"],
		`JSON field "type" must be "teams_token"`)
	assert.Equal(t, "AAA", obj["access_token"],
		`JSON field "access_token" must equal the stored access token`)
	assert.Equal(t, "RRR", obj["refresh_token"],
		`JSON field "refresh_token" must equal the stored refresh token`)
}

// ---------------------------------------------------------------------------
// saveTeamsTokenFile — round-trip through teamsEnumReadTokenFile
// ---------------------------------------------------------------------------

// TestSaveTeamsTokenFile_RoundTripsThroughReader saves a TokenSet to disk and
// then loads it back with the existing teamsEnumReadTokenFile parser (the same
// parser used by "enum teams users --token-file").  This proves that the
// credential-store format is binary-compatible with the token-file loader.
func TestSaveTeamsTokenFile_RoundTripsThroughReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teams.json")

	tok := &teams.TokenSet{
		AccessToken:  "AAA",
		RefreshToken: "RRR",
		IDToken:      "III",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        teams.DefaultScope,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}

	require.NoError(t, saveTeamsTokenFile(path, tok))

	// Load through the existing parser that "enum teams users" uses.
	gotAccess, gotRefresh, err := teamsEnumReadTokenFile(path)
	require.NoError(t, err, "teamsEnumReadTokenFile must parse the saved file without error")

	assert.Equal(t, "AAA", gotAccess,
		"round-trip access token must match what was saved")
	assert.Equal(t, "RRR", gotRefresh,
		"round-trip refresh token must match what was saved")
}

// ---------------------------------------------------------------------------
// saveTeamsTokenFile — creates missing directory
// ---------------------------------------------------------------------------

// TestSaveTeamsTokenFile_CreatesMissingDir verifies that saveTeamsTokenFile
// creates any missing parent directories (mode 0700) before writing the file.
func TestSaveTeamsTokenFile_CreatesMissingDir(t *testing.T) {
	base := t.TempDir()
	// sub/dir does not exist yet.
	path := filepath.Join(base, "sub", "dir", "teams.json")

	tok := &teams.TokenSet{
		AccessToken:  "AAA",
		RefreshToken: "RRR",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}

	err := saveTeamsTokenFile(path, tok)
	require.NoError(t, err, "saveTeamsTokenFile must create missing parent dirs and write the file")

	// File must exist.
	fi, err := os.Stat(path)
	require.NoError(t, err, "token file must exist after saveTeamsTokenFile creates missing dirs")
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	// Deepest created directory must be mode 0700.
	di, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
}

// ---------------------------------------------------------------------------
// End-to-end auto-load path resolution (no cobra command invocation)
// ---------------------------------------------------------------------------

// TestTeamsAutoLoad_DefaultPathRoundTrip simulates the load path that
// "enum teams users" would follow when no --token-file flag is provided:
//
//  1. Determine the default token path via teamsDefaultTokenPath.
//  2. Write a TokenSet at that path via saveTeamsTokenFile.
//  3. Load it back via teamsEnumReadTokenFile.
//
// No cobra commands, device-code flows, or network calls are made.
func TestTeamsAutoLoad_DefaultPathRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Step 1: resolve path.
	path, err := teamsDefaultTokenPath()
	require.NoError(t, err)

	// Step 2: write a token there.
	tok := &teams.TokenSet{
		AccessToken:  "AAA",
		RefreshToken: "RRR",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, saveTeamsTokenFile(path, tok))

	// Step 3: read it back the same way "enum teams users" would.
	gotAccess, gotRefresh, err := teamsEnumReadTokenFile(path)
	require.NoError(t, err)

	assert.Equal(t, "AAA", gotAccess)
	assert.Equal(t, "RRR", gotRefresh)
}

// ---------------------------------------------------------------------------
// P0-1: error messages must not leak token values
// ---------------------------------------------------------------------------

// TestSaveTeamsTokenFile_ErrorDoesNotLeakTokens (P0-1) verifies that when
// saveTeamsTokenFile fails (unwritable path), the returned error message does
// not contain any of the sensitive token string values.
//
// This is the P0-1 security requirement: token values must never appear in
// error output, logs, or diagnostic messages.
func TestSaveTeamsTokenFile_ErrorDoesNotLeakTokens(t *testing.T) {
	// Use a path that is structurally unwritable: a non-existent sub-path of
	// /dev/null (which is a character device, not a directory).
	path := "/dev/null/x/teams.json"

	tok := &teams.TokenSet{
		AccessToken:  "SECRET_ACCESS_TOKEN",
		RefreshToken: "SECRET_REFRESH_TOKEN",
		IDToken:      "SECRET_ID_TOKEN",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}

	err := saveTeamsTokenFile(path, tok)
	require.Error(t, err, "saveTeamsTokenFile must return an error for an unwritable path")

	errMsg := err.Error()

	assert.NotContains(t, errMsg, tok.AccessToken,
		"P0-1: error message must not contain the access token value")
	assert.NotContains(t, errMsg, tok.RefreshToken,
		"P0-1: error message must not contain the refresh token value")
	assert.NotContains(t, errMsg, tok.IDToken,
		"P0-1: error message must not contain the ID token value")
}
