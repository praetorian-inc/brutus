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

package clisurface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeRepo lays out a temporary repository with a README carrying both
// generated regions, and returns its root.
func newFakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, READMEPath), []byte(strings.Join([]string{
		"# tool",
		"",
		"## Quick Start",
		"",
		BeginMarker(RegionSubcommands),
		"stale listing",
		EndMarker(RegionSubcommands),
		"",
		BeginMarker(RegionAliases),
		"stale aliases",
		EndMarker(RegionAliases),
		"",
		"hand-written tail",
		"",
	}, "\n")), 0o644))
	return root
}

func TestArtifactsRendersEveryGeneratedFile(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())

	artifacts, err := Artifacts(root, s)
	require.NoError(t, err)

	require.Len(t, artifacts, 3)
	assert.Equal(t, []string{JSONPath, MarkdownPath, READMEPath}, []string{
		artifacts[0].Path, artifacts[1].Path, artifacts[2].Path,
	}, "artifacts come back in a stable order")
	assert.Equal(t, GeneratedPaths(), []string{artifacts[0].Path, artifacts[1].Path, artifacts[2].Path})

	readme := string(artifacts[2].Content)
	assert.Contains(t, readme, "hand-written tail", "the hand-written parts of README.md survive")
	assert.NotContains(t, readme, "stale listing", "the generated region is replaced")
	assert.Contains(t, readme, "into these focused subcommands")
	assert.Contains(t, readme, "| `scan` | `sc`, `scanner` |")
}

func TestArtifactsFailsLoudlyWhenTheREADMEHasNoRegionMarkers(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, READMEPath), []byte("# tool\n"), 0o644))

	_, err := Artifacts(root, Walk(newTestTree()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "splicing region \"cli-subcommands\" into README.md")
}

func TestArtifactsFailsWhenTheREADMEIsMissing(t *testing.T) {
	_, err := Artifacts(t.TempDir(), Walk(newTestTree()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading README.md")
}

func TestWriteThenCheckIsClean(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())

	require.NoError(t, Write(root, s))

	stale, err := CheckArtifacts(root, s)
	require.NoError(t, err)
	assert.Empty(t, stale, "freshly written artifacts are not stale")

	for _, rel := range GeneratedPaths() {
		_, statErr := os.Stat(filepath.Join(root, rel))
		require.NoError(t, statErr, "%s must exist on disk", rel)
	}
}

func TestWriteIsIdempotent(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())

	require.NoError(t, Write(root, s))
	first := readAll(t, root)
	require.NoError(t, Write(root, s))
	second := readAll(t, root)

	assert.Equal(t, first, second, "regenerating twice must produce byte-identical files")
}

func TestCheckArtifactsNamesTheStaleFileAndTheFirstDifference(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())
	require.NoError(t, Write(root, s))

	// Hand-edit the generated reference, the way a well-meaning contributor would.
	mdPath := filepath.Join(root, MarkdownPath)
	content, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	edited := strings.Replace(string(content), "# tool CLI reference", "# Tool CLI Reference", 1)
	require.NoError(t, os.WriteFile(mdPath, []byte(edited), 0o644))

	stale, err := CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 1)
	assert.Equal(t, MarkdownPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, `line 3 is "# Tool CLI Reference", generated content has "# tool CLI reference"`)
	assert.Contains(t, stale[0].String(), "docs/CLI.md is stale")
	assert.Contains(t, stale[0].String(), "Regenerate it with 'make cli-docs'")
}

func TestCheckArtifactsReportsMissingFiles(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())

	stale, err := CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 3, "nothing has been generated yet: the JSON and markdown are missing and the README is stale")
	assert.Equal(t, JSONPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, "cannot be read")
}

func TestCheckArtifactsReportsATruncatedFile(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())
	require.NoError(t, Write(root, s))

	// A truncation that keeps every surviving line identical can only be
	// described by the line counts.
	full, err := os.ReadFile(filepath.Join(root, JSONPath))
	require.NoError(t, err)
	truncated := strings.Join(strings.Split(string(full), "\n")[:3], "\n")
	require.NoError(t, os.WriteFile(filepath.Join(root, JSONPath), []byte(truncated), 0o644))

	stale, err := CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 1)
	assert.Equal(t, JSONPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, "committed content has 3 lines, generated content has")
}

func TestLintRepoChecksMarkdownAndGoComments(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())
	require.NoError(t, Write(root, s))

	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"),
		[]byte("Run `tool scan --target host`.\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "guide.md"),
		[]byte("```bash\ntool scan --removed-flag\n```\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cmd", "tool", "main.go"),
		[]byte("package main\n\n// handles the --gone-from-comments mode.\nfunc main() {}\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pkg", "lib", "lib.go"),
		[]byte("package lib\n\n// Uses --timeout, which still exists.\nconst A = 1\n"), 0o644))

	issues, err := LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 2)
	assert.Equal(t, "cmd/tool/main.go", issues[0].File, "issues are sorted by file then line")
	assert.Equal(t, "--gone-from-comments", issues[0].Token)
	assert.Equal(t, "docs/guide.md", issues[1].File)
	assert.Equal(t, "--removed-flag", issues[1].Token)
}

func TestLintRepoAcceptsTheDocumentsItJustGenerated(t *testing.T) {
	root := newFakeRepo(t)
	s := Walk(newTestTree())
	require.NoError(t, Write(root, s))
	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"), []byte("Run `make cli-docs`.\n"), 0o644))

	issues, err := LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues,
		"the generated reference and README regions must lint clean against the surface they came from")
}

func TestLintRepoSurvivesAMissingDocsDirectory(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, READMEPath), []byte("# tool\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"), []byte("hi\n"), 0o644))

	issues, err := LintRepo(root, Walk(newTestTree()), emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestLintRepoFailsWhenAConfiguredDocumentIsMissing(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, READMEPath), []byte("# tool\n"), 0o644))

	_, err := LintRepo(root, Walk(newTestTree()), emptyAllowlist(t))
	require.Error(t, err, "a document the linter is configured to read must not be skipped silently")
	assert.Contains(t, err.Error(), "reading CONTRIBUTING.md")
}

func TestLoadAllowlist(t *testing.T) {
	root := t.TempDir()

	allow, err := LoadAllowlist(root)
	require.NoError(t, err, "a missing allowlist is an empty allowlist, not an error")
	assert.Empty(t, allow.Entries())

	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, AllowlistPath),
		[]byte("--old-name # renamed in v1.9, the migration note has to name it\n"), 0o644))

	allow, err = LoadAllowlist(root)
	require.NoError(t, err)
	assert.Equal(t, []string{"--old-name"}, allow.Entries())

	require.NoError(t, os.WriteFile(filepath.Join(root, AllowlistPath), []byte("--no-reason\n"), 0o644))
	_, err = LoadAllowlist(root)
	require.Error(t, err, "an entry without a reason is a hard error")
}

func TestFindRepoRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/tool\n"), 0o644))
	nested := filepath.Join(root, "cmd", "tool")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	found, err := FindRepoRoot(nested)
	require.NoError(t, err)
	assert.Equal(t, root, found, "the root is the nearest ancestor holding go.mod")

	_, err = FindRepoRoot(filepath.Join(t.TempDir(), "nowhere"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no go.mod found")
}

// readAll reads every generated artifact into a map keyed by repo-relative path.
func readAll(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range GeneratedPaths() {
		content, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err)
		out[rel] = string(content)
	}
	return out
}
