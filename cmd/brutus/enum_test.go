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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsEnumSubcommand(t *testing.T) {
	tests := []struct {
		args     []string
		expected bool
	}{
		{[]string{"brutus", "enum", "-e", "user@test.com"}, true},
		{[]string{"brutus", "enum"}, true},
		{[]string{"brutus", "--target", "host:22"}, false},
		{[]string{"brutus"}, false},
	}

	for _, tt := range tests {
		result := isEnumSubcommand(tt.args)
		assert.Equal(t, tt.expected, result, "args: %v", tt.args)
	}
}

func TestLoadEnumEmails_SingleFlag(t *testing.T) {
	emails, err := loadEnumEmails("user@test.com", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"user@test.com"}, emails)
}

func TestLoadEnumEmails_CommaSeparated(t *testing.T) {
	emails, err := loadEnumEmails("a@test.com,b@test.com", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"a@test.com", "b@test.com"}, emails)
}

func TestLoadEnumEmails_CommaSeparatedWithSpaces(t *testing.T) {
	emails, err := loadEnumEmails("a@test.com, b@test.com , c@test.com", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"a@test.com", "b@test.com", "c@test.com"}, emails)
}


func TestLoadEnumEmails_Empty(t *testing.T) {
	emails, err := loadEnumEmails("", "")
	require.NoError(t, err)
	assert.Empty(t, emails)
}

func TestLoadEnumEmails_FileNotFound(t *testing.T) {
	_, err := loadEnumEmails("", "/nonexistent/file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "opening email file")
}

func TestLoadEnumEmails_FromFile(t *testing.T) {
	tmpFile := t.TempDir() + "/emails.txt"
	content := "user1@test.com\nuser2@test.com\n# comment\n\nuser3@test.com\n"
	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0o600))

	emails, err := loadEnumEmails("", tmpFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"user1@test.com", "user2@test.com", "user3@test.com"}, emails)
}

func TestLoadEnumEmails_BothFlagAndFile(t *testing.T) {
	tmpFile := t.TempDir() + "/emails.txt"
	content := "file@test.com\n"
	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0o600))

	emails, err := loadEnumEmails("flag@test.com", tmpFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"flag@test.com", "file@test.com"}, emails)
}
