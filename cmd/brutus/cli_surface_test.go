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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/clisurface"
)

// updateGoldens rewrites the generated CLI-surface artifacts instead of
// checking them. "make cli-docs" is the documented way to set it.
var updateGoldens = flag.Bool("update", false,
	"rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

// cliDocs builds the Docs every test in this file reads its paths, its regions
// and its regenerate command from. The SDK's defaults for the four paths and
// the two README regions are already the layout brutus commits, and leaving
// them unset is what keeps that layout a single documented default rather than
// a copy of one.
//
// The two lint scopes are the exception, and are stated here rather than
// defaulted. The SDK's LintedMarkdown default is READMEPath alone, while this
// gate has policed CONTRIBUTING.md since it was written -- a document that
// names brutus throughout, and so one that drifts. LintedGoDirs is spelled out
// beside it although it currently equals the SDK default, because the point is
// not the value: brutus's lint scope is a decision brutus owns, and pinning it
// locally is what keeps a future change to an SDK default from narrowing this
// gate's reach silently.
//
// It is a constructor rather than a package-level value so a configuration
// that stopped validating fails the test that uses it, with New's error,
// instead of panicking during package initialization where no test owns the
// failure.
func cliDocs(t *testing.T) *clisurface.Docs {
	t.Helper()
	docs, err := clisurface.New(clisurface.Config{
		RegenerateCommand: "make cli-docs",
		// "README.md" is spelled out rather than shared with READMEPath just
		// above its default: the SDK keeps that default unexported, and a
		// composite literal cannot read the field it is initializing.
		LintedMarkdown: []string{"README.md", "CONTRIBUTING.md"},
		LintedGoDirs:   []string{"cmd", "internal", "pkg"},
	})
	require.NoError(t, err)
	return docs
}

// TestCLISurface is the drift gate. It walks the live cobra tree, compares it
// against the committed surface, and compares the committed generated files
// against what that surface renders. Without -update it never writes.
func TestCLISurface(t *testing.T) {
	docs := cliDocs(t)
	cfg := docs.Config()
	root := repoRoot(t)
	live := clisurface.Walk(rootCmd)

	if *updateGoldens {
		require.NoError(t, docs.Write(root, live))
		t.Logf("regenerated %s", strings.Join(docs.GeneratedPaths(), ", "))
		return
	}

	golden, err := os.ReadFile(filepath.Join(root, cfg.JSONPath))
	require.NoErrorf(t, err, "%s is missing; create it with %q", cfg.JSONPath, cfg.RegenerateCommand)
	documented, err := docs.ParseJSON(golden)
	require.NoError(t, err)

	// Fail with require.Fail rather than require.Empty: Empty dumps the raw
	// findings slice on one unwrapped line before printing the formatted
	// message, so every finding prints twice, once unreadable and once
	// formatted. Fail only prints the formatted report.
	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift", docs.Report(findings))
	}

	stale, err := docs.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

// TestCLISurfaceDocLint fails when a document or a Go comment names a flag or a
// subcommand the CLI does not accept.
func TestCLISurfaceDocLint(t *testing.T) {
	docs := cliDocs(t)
	root := repoRoot(t)
	allow, err := docs.LoadAllowlist(root)
	require.NoError(t, err)

	issues, scope, err := docs.LintRepo(root, clisurface.Walk(rootCmd), allow)
	require.NoError(t, err)

	// Log the scope on a pass as well as a failure. An empty issue list is
	// only good news if the run actually read something, and a lint walk that
	// silently reached nothing -- a renamed directory, an allowlist that grew
	// to cover everything, entries skipped for not being regular files --
	// reads exactly like a clean repository. LintReport prints this on a
	// failure; the log is how a passing run says it too. Named fields rather
	// than %+v: LintScope has no String method, so a verb would dump its
	// internals. GoFiles is a count and not a list because brutus has hundreds
	// of them, which is the same choice LintReport's own coverage line makes.
	t.Logf("linted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted; skipped %d entr(y/ies) that are not regular files [%s]",
		len(scope.MarkdownFiles), scopeList(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeList(scope.GoDirs),
		len(scope.Allowlist.Entries()),
		len(scope.SkippedIrregular), scopeList(scope.SkippedIrregular))

	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues, scope))
	}
}

// TestCLISurfaceGateDetectsRename proves the gate reddens. A gate only ever
// observed passing is not known to work, so this renames a real flag on the
// real tree and asserts the diff reports exactly that rename, then feeds the
// linter a document naming a removed flag and asserts it is reported with
// file:line.
func TestCLISurfaceGateDetectsRename(t *testing.T) {
	docs := cliDocs(t)
	documented := clisurface.Walk(rootCmd)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
		// This mutates a flag on the shared package-level logonCmd and restores it in
		// Cleanup. It is safe only because nothing in this package calls t.Parallel:
		// do not add it here or to any test that reads the command tree, or the two
		// will race on the rename. pflag also keys its lookup map by the original
		// name, so only VisitAll -- which is what Walk uses -- observes the change.
		flagObj := logonCmd.Flags().Lookup("experimental-ai")
		require.NotNil(t, flagObj, "the fixture flag must exist for this test to mean anything")
		t.Cleanup(func() { flagObj.Name = "experimental-ai" })
		flagObj.Name = "experimental-ay"

		findings := clisurface.Diff(documented, clisurface.Walk(rootCmd))

		require.Len(t, findings, 2, "a rename is exactly one removal and one addition, and nothing else:\n%s",
			docs.Report(findings))
		// Findings are sorted by command then flag name, so the old name
		// ("experimental-ai") is reported before the new one.
		assert.Equal(t, clisurface.FlagRemoved, findings[0].Kind)
		assert.Equal(t, "experimental-ai", findings[0].Flag)
		assert.Equal(t, "brutus logon", findings[0].Command)
		assert.Equal(t, clisurface.FlagUndocumented, findings[1].Kind)
		assert.Equal(t, "experimental-ay", findings[1].Flag)
		assert.Equal(t, "brutus logon", findings[1].Command)
		assert.Contains(t, findings[0].String(),
			`flag --experimental-ai on "brutus logon" is in the generated docs but cobra no longer accepts it`)
		assert.Contains(t, findings[1].String(),
			`flag --experimental-ay on "brutus logon" is registered by cobra but missing from the generated docs`)
	})

	t.Run("the tree is restored", func(t *testing.T) {
		assert.Empty(t, clisurface.Diff(documented, clisurface.Walk(rootCmd)),
			"the rename above must not leak into the rest of the suite")
	})

	t.Run("a document naming a removed flag is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Historic note.\n\n```bash\nbrutus logon --target host:3389 --sticky-keys-exec \"whoami\"\n```\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--sticky-keys-exec", issues[0].Token)
		assert.Equal(t, "brutus logon", issues[0].Command)
		assert.Contains(t, issues[0].String(),
			`docs/example.md:4: --sticky-keys-exec is not a flag of "brutus logon"`)
		assert.Contains(t, issues[0].String(), docs.Config().AllowlistPath,
			"the message says how to allow a deliberate mention")
	})

	t.Run("the allowlist suppresses a deliberate mention", func(t *testing.T) {
		allow, err := docs.ParseAllowlist("--sticky-keys-exec # renamed to --exec; the rename note names the old flag\n")
		require.NoError(t, err)

		doc := "```bash\nbrutus logon --sticky-keys-exec \"whoami\"\n```\n"
		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, allow))
	})

	t.Run("the logon family rejects the inherited --timeout", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "```bash\nbrutus logon --target host:3389 --timeout 30s\n```\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1,
			"--timeout is inherited from the root but guardLogonTimeoutFlag refuses it, so documenting it is drift")
		assert.Equal(t, "--timeout", issues[0].Token)
		assert.Contains(t, issues[0].Reason, "use --scan-timeout")
	})
}

// repoRoot locates the repository root; a test's working directory is its own
// package directory, and the generated artifacts are repo-relative.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := clisurface.FindRepoRoot(wd)
	require.NoError(t, err)
	return root
}

// stalenessReport renders stale artifacts one per line.
func stalenessReport(stale []clisurface.Staleness) string {
	lines := make([]string, 0, len(stale))
	for i := range stale {
		lines = append(lines, stale[i].String())
	}
	return strings.Join(lines, "\n")
}

// scopeList renders one LintScope path list for the coverage log, naming the
// empty list rather than logging an empty bracket a reader has to interpret.
// The SDK renders its own report the same way, but with an unexported helper.
func scopeList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
