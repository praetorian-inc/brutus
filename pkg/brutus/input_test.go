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

package brutus

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPasswordsFromFile_EmptyMarker(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `admin
<EMPTY>
password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	passwords, err := LoadPasswordsFromFile(passwordFile)
	require.NoError(t, err)
	require.Len(t, passwords, 3)
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "", passwords[1], "second password should be empty (from <EMPTY> marker)")
	assert.Equal(t, "password123", passwords[2])
}

func TestLoadPasswordsFromFile_EmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `admin

password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	passwords, err := LoadPasswordsFromFile(passwordFile)
	require.NoError(t, err)
	require.Len(t, passwords, 3, "should have 3 passwords including empty line")
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "", passwords[1], "second password should be empty (from empty line)")
	assert.Equal(t, "password123", passwords[2])
}

func TestLoadPasswordsFromFile_CommentsSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "passwords.txt")

	content := `# This is a comment
admin
# Another comment
password123
`
	err := os.WriteFile(passwordFile, []byte(content), 0o644)
	require.NoError(t, err)

	passwords, err := LoadPasswordsFromFile(passwordFile)
	require.NoError(t, err)
	require.Len(t, passwords, 2, "should have 2 passwords (comments skipped)")
	assert.Equal(t, "admin", passwords[0])
	assert.Equal(t, "password123", passwords[1])
}

func TestLoadPasswordsFromFile_FileNotFound(t *testing.T) {
	_, err := LoadPasswordsFromFile("/nonexistent/file.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening password file")
}

func TestLoadUsernamesFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	usernameFile := filepath.Join(tmpDir, "usernames.txt")

	content := `# Default usernames
root
admin

# Service accounts
postgres
mysql
`
	err := os.WriteFile(usernameFile, []byte(content), 0o644)
	require.NoError(t, err)

	usernames, err := LoadUsernamesFromFile(usernameFile)
	require.NoError(t, err)
	require.Len(t, usernames, 4, "should have 4 usernames (comments and empty lines skipped)")
	assert.Equal(t, "root", usernames[0])
	assert.Equal(t, "admin", usernames[1])
	assert.Equal(t, "postgres", usernames[2])
	assert.Equal(t, "mysql", usernames[3])
}

func TestLoadUsernamesFromFile_FileNotFound(t *testing.T) {
	_, err := LoadUsernamesFromFile("/nonexistent/usernames.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening username file")
}

func TestLoadKeyFile_FileNotFound(t *testing.T) {
	_, err := LoadKeyFile("/nonexistent/key.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accessing key file")
}

func TestLoadKeyFile_Empty(t *testing.T) {
	keys, err := LoadKeyFile("")
	require.NoError(t, err)
	assert.Nil(t, keys)
}
