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

// TestLoadPasswords_EmptyPassword tests that empty passwords can be loaded
// when the -p flag is explicitly set to an empty string
func TestLoadPasswords_EmptyPassword(t *testing.T) {
	// Test: -p '' (flag explicitly set to empty string)
	// Expected: should include empty password in the list
	passwords, err := loadPasswords("", "", true)
	require.NoError(t, err)
	require.Len(t, passwords, 1, "should have exactly one password (empty)")
	assert.Equal(t, "", passwords[0], "password should be empty string")
}

// TestLoadPasswords_NoFlag tests that when -p flag is not provided,
// no passwords are loaded from inline
func TestLoadPasswords_NoFlag(t *testing.T) {
	// Test: flag not set (default empty string, but flag not explicitly provided)
	// Expected: should return empty list (no passwords)
	passwords, err := loadPasswords("", "", false)
	require.NoError(t, err)
	assert.Empty(t, passwords, "should have no passwords when flag not set")
}

// TestLoadPasswords_InlineWithCommaSeparated tests comma-separated inline passwords
func TestLoadPasswords_InlineWithCommaSeparated(t *testing.T) {
	// Test normal comma-separated passwords
	passwords, err := loadPasswords("admin,password,test123", "", true)
	require.NoError(t, err)
	require.Len(t, passwords, 3)
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "password", passwords[1])
	assert.Equal(t, "test123", passwords[2])
}

// TestLoadPasswords_InlineAndFile tests combining inline and file passwords
func TestLoadPasswords_InlineAndFile(t *testing.T) {
	// Create temporary password file
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `file1
file2
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	// Test combining inline and file
	passwords, err := loadPasswords("inline1,inline2", passwordFile, true)
	require.NoError(t, err)
	require.Len(t, passwords, 4)
	assert.Equal(t, "inline1", passwords[0])
	assert.Equal(t, "inline2", passwords[1])
	assert.Equal(t, "file1", passwords[2])
	assert.Equal(t, "file2", passwords[3])
}

// TestLoadUsernames_InlineOnly tests comma-separated inline usernames
func TestLoadUsernames_InlineOnly(t *testing.T) {
	usernames, err := loadUsernames("root,admin,ubuntu", "", true)
	require.NoError(t, err)
	require.Len(t, usernames, 3)
	assert.Equal(t, "root", usernames[0])
	assert.Equal(t, "admin", usernames[1])
	assert.Equal(t, "ubuntu", usernames[2])
}

// TestLoadUsernames_InlineAndFile tests combining inline and file usernames
func TestLoadUsernames_InlineAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	usernameFile := filepath.Join(tmpDir, "usernames.txt")

	content := `fileuser1
fileuser2
`
	err := os.WriteFile(usernameFile, []byte(content), 0o644)
	require.NoError(t, err)

	usernames, err := loadUsernames("inlineuser1,inlineuser2", usernameFile, true)
	require.NoError(t, err)
	require.Len(t, usernames, 4)
	assert.Equal(t, "inlineuser1", usernames[0])
	assert.Equal(t, "inlineuser2", usernames[1])
	assert.Equal(t, "fileuser1", usernames[2])
	assert.Equal(t, "fileuser2", usernames[3])
}

// TestLoadUsernames_EmptyInlineNoFile tests that empty inline with no file returns empty list
func TestLoadUsernames_EmptyInlineNoFile(t *testing.T) {
	usernames, err := loadUsernames("", "", false)
	require.NoError(t, err)
	assert.Empty(t, usernames, "should have no usernames when both inline and file are empty")
}

// TestLoadUsernames_DefaultIgnoredWhenFileProvided tests that the default -u value
// is NOT included when -U is provided but -u is not explicitly set
func TestLoadUsernames_DefaultIgnoredWhenFileProvided(t *testing.T) {
	tmpDir := t.TempDir()
	usernameFile := filepath.Join(tmpDir, "usernames.txt")

	content := "postgres\nmysql\n"
	err := os.WriteFile(usernameFile, []byte(content), 0o644)
	require.NoError(t, err)

	// Simulates: brutus -U usernames.txt (without -u)
	// The inline value "root,admin" is the DEFAULT, but inlineFlagSet is false
	usernames, err := loadUsernames("root,admin", usernameFile, false)
	require.NoError(t, err)
	require.Len(t, usernames, 2, "should only have file usernames, not defaults")
	assert.Equal(t, "postgres", usernames[0])
	assert.Equal(t, "mysql", usernames[1])
}

func TestValidateKeyFileFlags(t *testing.T) {
	// -k without explicit -u or -U should fail
	err := validateKeyFileFlags("key.pem", false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "-k requires -u or -U")

	// -k with explicit -u should pass
	err = validateKeyFileFlags("key.pem", true, "")
	require.NoError(t, err)

	// -k with -U should pass
	err = validateKeyFileFlags("key.pem", false, "users.txt")
	require.NoError(t, err)

	// No -k should always pass
	err = validateKeyFileFlags("", false, "")
	require.NoError(t, err)
}
