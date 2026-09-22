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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

func TestPageSizeForLimit(t *testing.T) {
	assert.Equal(t, 100, pageSizeForLimit(0), "unbounded limit uses default page size")
	assert.Equal(t, 100, pageSizeForLimit(-1))
	assert.Equal(t, 1, pageSizeForLimit(1))
	assert.Equal(t, 50, pageSizeForLimit(50))
	assert.Equal(t, 100, pageSizeForLimit(100))
	assert.Equal(t, 100, pageSizeForLimit(101), "page size never exceeds 100")
}

func TestLoadLinesFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	require.NoError(t, os.WriteFile(path, []byte("# comment\n\nalice\n  bob  \n#skip\ncharlie\n"), 0o644))

	got, err := loadLinesFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, got)

	_, err = loadLinesFromFile(filepath.Join(t.TempDir(), "missing.txt"))
	require.Error(t, err)
}

func TestRunEnumGenerate_UsernamesOnly(t *testing.T) {
	origDomain, origFormat, origLimit := flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit
	t.Cleanup(func() {
		flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit = origDomain, origFormat, origLimit
	})
	flagEnumDomain = ""
	flagEnumFormat = enum.FormatFirstDotLast
	flagEnumGenerateLimit = 3

	out := captureStdout(t, func() {
		require.NoError(t, runEnumGenerate(nil, nil))
	})
	lines := nonEmptyLines(out)
	require.Len(t, lines, 3)
	for _, line := range lines {
		assert.NotContains(t, line, "@")
		assert.Contains(t, line, ".")
	}
}

func TestRunEnumGenerate_Emails(t *testing.T) {
	origDomain, origFormat, origLimit := flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit
	t.Cleanup(func() {
		flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit = origDomain, origFormat, origLimit
	})
	flagEnumDomain = "example.com"
	flagEnumFormat = enum.FormatFirstDotLast
	flagEnumGenerateLimit = 2

	out := captureStdout(t, func() {
		require.NoError(t, runEnumGenerate(nil, nil))
	})
	lines := nonEmptyLines(out)
	require.Len(t, lines, 2)
	for _, line := range lines {
		assert.True(t, strings.HasSuffix(line, "@example.com"), line)
	}
}

func TestRunEnumGenerate_UnknownFormatEmpty(t *testing.T) {
	origDomain, origFormat, origLimit := flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit
	t.Cleanup(func() {
		flagEnumDomain, flagEnumFormat, flagEnumGenerateLimit = origDomain, origFormat, origLimit
	})
	flagEnumDomain = ""
	flagEnumFormat = "not-a-format"
	flagEnumGenerateLimit = 10

	out := captureStdout(t, func() {
		require.NoError(t, runEnumGenerate(nil, nil))
	})
	assert.Empty(t, strings.TrimSpace(out))
}

func TestEnumNamesByEmail(t *testing.T) {
	targets := []enum.Target{
		{Email: "generated@ex.com", First: "Ada", Last: "Lovelace"},
		{Email: "supplied@ex.com"},
	}
	names := enumNamesByEmail(targets)
	assert.Equal(t, []string{"generated@ex.com", "supplied@ex.com"}, enumTargetEmails(targets))

	first, last := enumNameFor(names, "generated@ex.com")
	assert.Equal(t, "Ada", first)
	assert.Equal(t, "Lovelace", last)

	first, last = enumNameFor(names, "supplied@ex.com")
	assert.Empty(t, first)
	assert.Empty(t, last)

	first, last = enumNameFor(names, "missing@ex.com")
	assert.Empty(t, first)
	assert.Empty(t, last)
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}
