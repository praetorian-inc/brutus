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
	passwords := loadPasswords("", "", true)
	require.Len(t, passwords, 1, "should have exactly one password (empty)")
	assert.Equal(t, "", passwords[0], "password should be empty string")
}

// TestLoadPasswords_NoFlag tests that when -p flag is not provided,
// no passwords are loaded from inline
func TestLoadPasswords_NoFlag(t *testing.T) {
	// Test: flag not set (default empty string, but flag not explicitly provided)
	// Expected: should return empty list (no passwords)
	passwords := loadPasswords("", "", false)
	assert.Empty(t, passwords, "should have no passwords when flag not set")
}

// TestLoadPasswords_EmptyMarkerInFile tests that <EMPTY> marker in password file
// is converted to an empty password
func TestLoadPasswords_EmptyMarkerInFile(t *testing.T) {
	// Create temporary password file with <EMPTY> marker
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `admin
<EMPTY>
password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	// Test loading passwords from file
	passwords := loadPasswords("", passwordFile, false)
	require.Len(t, passwords, 3, "should have 3 passwords")
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "", passwords[1], "second password should be empty (from <EMPTY> marker)")
	assert.Equal(t, "password123", passwords[2])
}

// TestLoadPasswords_EmptyLinesInFile tests that empty lines in password file
// are treated as empty passwords
func TestLoadPasswords_EmptyLinesInFile(t *testing.T) {
	// Create temporary password file with empty lines
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `admin

password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	// Test loading passwords from file
	passwords := loadPasswords("", passwordFile, false)
	require.Len(t, passwords, 3, "should have 3 passwords including empty line")
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "", passwords[1], "second password should be empty (from empty line)")
	assert.Equal(t, "password123", passwords[2])
}

// TestLoadPasswords_CommentsSkipped tests that comment lines are skipped
func TestLoadPasswords_CommentsSkipped(t *testing.T) {
	// Create temporary password file with comments
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `# This is a comment
admin
# Another comment
password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	// Test loading passwords from file
	passwords := loadPasswords("", passwordFile, false)
	require.Len(t, passwords, 2, "should have 2 passwords (comments skipped)")
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "password123", passwords[1])
}

// TestLoadPasswords_InlineWithCommaSeparated tests comma-separated inline passwords
func TestLoadPasswords_InlineWithCommaSeparated(t *testing.T) {
	// Test normal comma-separated passwords
	passwords := loadPasswords("admin,password,test123", "", true)
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
	passwords := loadPasswords("inline1,inline2", passwordFile, true)
	require.Len(t, passwords, 4)
	assert.Equal(t, "inline1", passwords[0])
	assert.Equal(t, "inline2", passwords[1])
	assert.Equal(t, "file1", passwords[2])
	assert.Equal(t, "file2", passwords[3])
}
