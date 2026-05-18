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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// parseCredentialPairs
// ---------------------------------------------------------------------------

func TestParseCredentialPairs_Basic(t *testing.T) {
	creds, err := parseCredentialPairs("admin:admin,root:toor")
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "admin", creds[0].Password)
	assert.Equal(t, "root", creds[1].Username)
	assert.Equal(t, "toor", creds[1].Password)
}

func TestParseCredentialPairs_SinglePair(t *testing.T) {
	creds, err := parseCredentialPairs("admin:secret")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "secret", creds[0].Password)
}

func TestParseCredentialPairs_ColonInPassword(t *testing.T) {
	// strings.Cut splits on the first colon only
	creds, err := parseCredentialPairs("admin:pass:word")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "pass:word", creds[0].Password)
}

func TestParseCredentialPairs_MultipleColonsInPassword(t *testing.T) {
	creds, err := parseCredentialPairs("sa:p@ss:w0rd:123")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "sa", creds[0].Username)
	assert.Equal(t, "p@ss:w0rd:123", creds[0].Password)
}

func TestParseCredentialPairs_EmptyPassword(t *testing.T) {
	creds, err := parseCredentialPairs("admin:")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "", creds[0].Password)
}

func TestParseCredentialPairs_SpecialCharacters(t *testing.T) {
	creds, err := parseCredentialPairs("admin:p@ss!w0rd#$%^&*()")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "p@ss!w0rd#$%^&*()", creds[0].Password)
}

func TestParseCredentialPairs_WhitespaceAroundPairs(t *testing.T) {
	creds, err := parseCredentialPairs(" admin:pass , root:toor ")
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "admin:pass", creds[0].Username+":"+creds[0].Password)
	assert.Equal(t, "root:toor", creds[1].Username+":"+creds[1].Password)
}

func TestParseCredentialPairs_TrailingComma(t *testing.T) {
	creds, err := parseCredentialPairs("admin:pass,")
	require.NoError(t, err)
	require.Len(t, creds, 1, "trailing comma should be ignored")
	assert.Equal(t, "admin", creds[0].Username)
}

func TestParseCredentialPairs_EmptyString(t *testing.T) {
	creds, err := parseCredentialPairs("")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestParseCredentialPairs_OnlyCommas(t *testing.T) {
	creds, err := parseCredentialPairs(",,,")
	require.NoError(t, err)
	assert.Empty(t, creds, "only commas should produce no credentials")
}

func TestParseCredentialPairs_NoColon(t *testing.T) {
	_, err := parseCredentialPairs("nocolon")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected user:pass")
}

func TestParseCredentialPairs_MixedValidAndInvalid(t *testing.T) {
	// Should fail on first invalid pair
	_, err := parseCredentialPairs("admin:pass,invalid,root:toor")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

// ---------------------------------------------------------------------------
// loadCredentials
// ---------------------------------------------------------------------------

func TestLoadCredentials_InlineOnly(t *testing.T) {
	creds, err := loadCredentials("admin:pass,root:toor", "")
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "pass", creds[0].Password)
	assert.Equal(t, "root", creds[1].Username)
	assert.Equal(t, "toor", creds[1].Password)
}

func TestLoadCredentials_FileOnly(t *testing.T) {
	file := writeCredFile(t, "admin:password\nroot:toor\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "password", creds[0].Password)
	assert.Equal(t, "root", creds[1].Username)
	assert.Equal(t, "toor", creds[1].Password)
}

func TestLoadCredentials_Combined(t *testing.T) {
	file := writeCredFile(t, "file_user:file_pass\n")

	creds, err := loadCredentials("inline_user:inline_pass", file)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	// Inline comes first
	assert.Equal(t, "inline_user", creds[0].Username)
	assert.Equal(t, "inline_pass", creds[0].Password)
	// File comes second
	assert.Equal(t, "file_user", creds[1].Username)
	assert.Equal(t, "file_pass", creds[1].Password)
}

func TestLoadCredentials_NeitherProvided(t *testing.T) {
	creds, err := loadCredentials("", "")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestLoadCredentials_FileWithComments(t *testing.T) {
	file := writeCredFile(t, "# SSH credentials\nadmin:password\n# Database\nroot:toor\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	require.Len(t, creds, 2, "comments should be skipped")
	assert.Equal(t, "admin", creds[0].Username)
	assert.Equal(t, "root", creds[1].Username)
}

func TestLoadCredentials_FileWithBlankLines(t *testing.T) {
	file := writeCredFile(t, "admin:pass\n\n\nroot:toor\n\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	require.Len(t, creds, 2, "blank lines should be skipped")
}

func TestLoadCredentials_FileOnlyComments(t *testing.T) {
	file := writeCredFile(t, "# nothing here\n# just comments\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestLoadCredentials_FileColonInPassword(t *testing.T) {
	file := writeCredFile(t, "sa:p@ss:w0rd\nadmin:a:b:c\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "sa", creds[0].Username)
	assert.Equal(t, "p@ss:w0rd", creds[0].Password)
	assert.Equal(t, "admin", creds[1].Username)
	assert.Equal(t, "a:b:c", creds[1].Password)
}

func TestLoadCredentials_FileEmptyPassword(t *testing.T) {
	file := writeCredFile(t, "admin:\nroot:\n")

	creds, err := loadCredentials("", file)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	assert.Equal(t, "", creds[0].Password)
	assert.Equal(t, "", creds[1].Password)
}

func TestLoadCredentials_FileInvalidLine(t *testing.T) {
	file := writeCredFile(t, "admin:pass\nnocolon\nroot:toor\n")

	_, err := loadCredentials("", file)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nocolon")
	assert.Contains(t, err.Error(), "expected user:pass")
}

func TestLoadCredentials_FileNotFound(t *testing.T) {
	_, err := loadCredentials("", "/nonexistent/path/creds.txt")
	require.Error(t, err)
}

func TestLoadCredentials_InlineInvalid(t *testing.T) {
	_, err := loadCredentials("nocolon", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected user:pass")
}

// writeCredFile is a test helper that creates a temporary credentials file.
func writeCredFile(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "creds.txt")
	err := os.WriteFile(file, []byte(content), 0o600)
	require.NoError(t, err)
	return file
}
