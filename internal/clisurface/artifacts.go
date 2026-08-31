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
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LintedMarkdown are the hand-written documents whose examples and prose are
// checked against the surface, in addition to every file under docs/.
var LintedMarkdown = []string{READMEPath, "CONTRIBUTING.md"}

// LintedGoDirs are the trees whose Go comments are checked against the surface.
//
// internal/ is included: a comment naming a flag that no longer exists is the
// drift this gate was built for, and it does not become harmless by living
// outside cmd/ and pkg/. Adding it found two RDP comments still describing
// Vision confirmation as something a removed opt-out flag disabled, when it had
// become opt-in.
//
// A package whose subject is flag syntax has to write its placeholders in
// angle brackets rather than as bare dashed words, or its own documentation
// reads as a reference to a flag that does not exist. See this package's
// comments -- and note that this very comment had to be reworded, because the
// gate caught it naming the flags above.
var LintedGoDirs = []string{"cmd", "internal", "pkg"}

// FindRepoRoot walks up from start until it finds the directory holding go.mod.
// The gate runs as a test, whose working directory is the package directory, so
// it needs the repository root to read and write repo-relative artifacts.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", start, err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found in %s or any parent directory", start)
		}
		dir = parent
	}
}

// Artifact is one generated file and the content it must have.
type Artifact struct {
	// Path is repo-relative.
	Path string
	// Content is the full file content the surface renders to. For README.md
	// it is the on-disk file with the generated regions replaced.
	Content []byte
}

// Artifacts renders every generated artifact for s. README.md is spliced from
// its current on-disk content, so the hand-written parts of it are preserved.
func Artifacts(repoRoot string, s Surface) ([]Artifact, error) {
	jsonBytes, err := RenderJSON(s)
	if err != nil {
		return nil, err
	}

	readmePath := filepath.Join(repoRoot, READMEPath)
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", READMEPath, err)
	}
	spliced := string(readme)
	for _, region := range RenderRegions(s) {
		spliced, err = Splice(spliced, region.Name, region.Body)
		if err != nil {
			return nil, fmt.Errorf("splicing region %q into %s: %w", region.Name, READMEPath, err)
		}
	}

	return []Artifact{
		{Path: JSONPath, Content: jsonBytes},
		{Path: MarkdownPath, Content: RenderMarkdown(s)},
		{Path: READMEPath, Content: []byte(spliced)},
	}, nil
}

// Write writes every generated artifact. This is the -update path; the drift
// gate itself must never call it.
func Write(repoRoot string, s Surface) error {
	artifacts, err := Artifacts(repoRoot, s)
	if err != nil {
		return err
	}
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", artifacts[i].Path, err)
		}
		if err := os.WriteFile(path, artifacts[i].Content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", artifacts[i].Path, err)
		}
	}
	return nil
}

// Staleness is a generated artifact whose committed content no longer matches
// what the surface renders.
type Staleness struct {
	// Path is the repo-relative artifact.
	Path string
	// Detail says how it differs, naming the first differing line.
	Detail string
}

// String renders the staleness as one actionable line.
func (s Staleness) String() string {
	return fmt.Sprintf("%s is stale: %s. Regenerate it with '%s'", s.Path, s.Detail, RegenerateCommand)
}

// CheckArtifacts compares the committed artifacts against what the surface
// renders, without writing anything.
//
// Line endings are normalized before comparing. The repository carries no
// .gitattributes, so a contributor with core.autocrlf=true has CRLF on disk
// while the renderers emit LF — comparing raw bytes would report every
// generated file as stale on Windows, which is exactly the unexplained friction
// that gets a gate disabled.
func CheckArtifacts(repoRoot string, s Surface) ([]Staleness, error) {
	artifacts, err := Artifacts(repoRoot, s)
	if err != nil {
		return nil, err
	}

	var stale []Staleness
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
		onDisk, readErr := os.ReadFile(path)
		if readErr != nil {
			stale = append(stale, Staleness{Path: artifacts[i].Path, Detail: "cannot be read (" + readErr.Error() + ")"})
			continue
		}
		if bytes.Equal(normalizeNewlines(onDisk), normalizeNewlines(artifacts[i].Content)) {
			continue
		}
		stale = append(stale, Staleness{
			Path:   artifacts[i].Path,
			Detail: firstDifference(onDisk, artifacts[i].Content),
		})
	}
	return stale, nil
}

// normalizeNewlines rewrites CRLF to LF so that a checkout's line-ending
// convention cannot look like documentation drift.
func normalizeNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// firstDifference describes the first line where committed and generated
// content diverge. Both sides are normalized first, so the line it names is a
// real difference rather than an invisible carriage return.
func firstDifference(committed, generated []byte) string {
	got := strings.Split(string(normalizeNewlines(committed)), "\n")
	want := strings.Split(string(normalizeNewlines(generated)), "\n")
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] == want[i] {
			continue
		}
		return fmt.Sprintf("line %d is %q, generated content has %q", i+1, got[i], want[i])
	}
	return fmt.Sprintf("committed content has %d lines, generated content has %d", len(got), len(want))
}

// LoadAllowlist reads the deliberate-mention allowlist. A missing file is an
// empty allowlist, not an error.
func LoadAllowlist(repoRoot string) (Allowlist, error) {
	content, err := os.ReadFile(filepath.Join(repoRoot, AllowlistPath))
	switch {
	case os.IsNotExist(err):
		return ParseAllowlist("")
	case err != nil:
		return Allowlist{}, fmt.Errorf("reading %s: %w", AllowlistPath, err)
	}
	return ParseAllowlist(string(content))
}

// LintRepo checks every documented CLI reference in the repository against the
// surface: shell examples and prose in the markdown documents, and flag names
// in Go comments under cmd/ and pkg/. Issues come back sorted by file and line.
func LintRepo(repoRoot string, s Surface, allow Allowlist) ([]Issue, error) {
	var issues []Issue

	docs, err := lintedMarkdownFiles(repoRoot)
	if err != nil {
		return nil, err
	}
	for _, rel := range docs {
		content, readErr := os.ReadFile(filepath.Join(repoRoot, rel))
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", rel, readErr)
		}
		issues = append(issues, LintMarkdown(s, rel, string(content), allow)...)
	}

	goFiles, err := lintedGoFiles(repoRoot)
	if err != nil {
		return nil, err
	}
	for _, rel := range goFiles {
		src, readErr := os.ReadFile(filepath.Join(repoRoot, rel))
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", rel, readErr)
		}
		found, lintErr := LintGoComments(s, rel, src, allow)
		if lintErr != nil {
			return nil, lintErr
		}
		issues = append(issues, found...)
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		if issues[i].Line != issues[j].Line {
			return issues[i].Line < issues[j].Line
		}
		return issues[i].Token < issues[j].Token
	})
	return issues, nil
}

// lintedMarkdownFiles lists the markdown documents to check, sorted.
//
// The docs/ tree is walked recursively: a document that names a removed flag
// escapes the gate just as thoroughly from docs/guides/ as from docs/, and a
// check with a silent blind spot is worse than one whose reach is obvious.
func lintedMarkdownFiles(repoRoot string) ([]string, error) {
	files := append([]string(nil), LintedMarkdown...)

	docsRoot := filepath.Join(repoRoot, "docs")
	err := filepath.WalkDir(docsRoot, func(path string, d fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case d.IsDir(), !strings.HasSuffix(d.Name(), ".md"):
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("walking docs/: %w", err)
	}

	sort.Strings(files)
	return files, nil
}

// lintedGoFiles lists the Go files whose comments to check, sorted.
func lintedGoFiles(repoRoot string) ([]string, error) {
	var files []string
	for _, dir := range LintedGoDirs {
		root := filepath.Join(repoRoot, dir)
		if _, statErr := os.Stat(root); os.IsNotExist(statErr) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir(), !strings.HasSuffix(d.Name(), ".go"):
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", dir, err)
		}
	}
	sort.Strings(files)
	return files, nil
}

// LintReport renders lint issues as a failure message.
func LintReport(issues []Issue) string {
	var b strings.Builder
	fmt.Fprintf(&b, "documentation references %d CLI flag(s) or subcommand(s) that do not exist:\n\n", len(issues))
	for i := range issues {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, issues[i].String())
	}
	return strings.TrimRight(b.String(), "\n")
}
