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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/praetorian-inc/brutus/pkg/enum/teams"
)

// teamsTokenJSON is the on-disk / JSONL shape of a Teams TokenSet. It is the
// single source of truth shared by outputTeamsTokenJSONL (the -o/--json sink)
// and saveTeamsTokenFile (the default credential store), so both writers emit
// byte-identical output and remain compatible with teamsEnumReadTokenFile.
type teamsTokenJSON struct {
	Type         string    `json:"type"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// newTeamsTokenJSON maps a TokenSet onto the shared on-disk JSON shape.
func newTeamsTokenJSON(tok *teams.TokenSet) teamsTokenJSON {
	return teamsTokenJSON{
		Type:         "teams_token",
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
		ExpiresAt:    tok.ExpiresAt,
	}
}

// teamsDefaultTokenPath returns the default credential-store path
// (~/.brutus/teams.json) for the Teams auth flow.
func teamsDefaultTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".brutus", "teams.json"), nil
}

// saveTeamsTokenFile persists the full TokenSet to path in the same JSON shape
// that outputTeamsTokenJSONL writes, so the file is byte-compatible with -o
// output and the teamsEnumReadTokenFile parser. The parent directory is created
// with 0700 and the file is written with 0600. Token values are never logged;
// only path may appear in returned errors (P0-1).
func saveTeamsTokenFile(path string, tok *teams.TokenSet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating credential-store directory %q: %w", filepath.Dir(path), err)
	}

	data, err := json.Marshal(newTeamsTokenJSON(tok))
	if err != nil {
		return fmt.Errorf("encoding token for %q: %w", path, err)
	}

	// Open with O_NOFOLLOW so a pre-existing symlink at path is not followed
	// (an attacker could otherwise redirect the token write elsewhere). Token
	// values are never included in returned errors; only path may appear (P0-1).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|oNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("opening credential store %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing credential store %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing credential store %q: %w", path, err)
	}
	return nil
}
