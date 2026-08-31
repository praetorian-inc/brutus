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

	"github.com/praetorian-inc/brutus/internal/clisurface"
)

// updateGoldens rewrites the generated CLI-surface artifacts instead of
// checking them. "make cli-docs" is the documented way to set it.
var updateGoldens = flag.Bool("update", false,
	"rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

// TestCLISurface is the drift gate. It walks the live cobra tree, compares it
// against the committed surface, and compares the committed generated files
// against what that surface renders. Without -update it never writes.
func TestCLISurface(t *testing.T) {
	root := repoRoot(t)
	live := clisurface.Walk(rootCmd)

	if *updateGoldens {
		require.NoError(t, clisurface.Write(root, live))
		t.Logf("regenerated %s", strings.Join(clisurface.GeneratedPaths(), ", "))
		return
	}

	golden, err := os.ReadFile(filepath.Join(root, clisurface.JSONPath))
	require.NoErrorf(t, err, "%s is missing; create it with %q", clisurface.JSONPath, clisurface.RegenerateCommand)
	documented, err := clisurface.ParseJSON(golden)
	require.NoError(t, err)

	// Fail with require.Fail rather than require.Empty: Empty dumps the raw
	// findings slice on one unwrapped line before printing the formatted
	// message, so every finding prints twice, once unreadable and once
	// formatted. Fail only prints the formatted report.
	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift",
			clisurface.Report(findings, clisurface.GeneratedPaths(), clisurface.RegenerateCommand))
	}

	stale, err := clisurface.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

// TestCLISurfaceDocLint fails when a document or a Go comment names a flag or a
// subcommand the CLI does not accept.
func TestCLISurfaceDocLint(t *testing.T) {
	root := repoRoot(t)
	allow, err := clisurface.LoadAllowlist(root)
	require.NoError(t, err)

	issues, err := clisurface.LintRepo(root, clisurface.Walk(rootCmd), allow)
	require.NoError(t, err)
	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues))
	}
}

// TestCLISurfaceGateDetectsRename proves the gate reddens. A gate only ever
// observed passing is not known to work, so this renames a real flag on the
// real tree and asserts the diff reports exactly that rename, then feeds the
// linter a document naming a removed flag and asserts it is reported with
// file:line.
func TestCLISurfaceGateDetectsRename(t *testing.T) {
	documented := clisurface.Walk(rootCmd)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
		flagObj := logonCmd.Flags().Lookup("experimental-ai")
		require.NotNil(t, flagObj, "the fixture flag must exist for this test to mean anything")
		t.Cleanup(func() { flagObj.Name = "experimental-ai" })
		flagObj.Name = "experimental-ay"

		findings := clisurface.Diff(documented, clisurface.Walk(rootCmd))

		require.Len(t, findings, 2, "a rename is exactly one removal and one addition, and nothing else:\n%s",
			clisurface.Report(findings, clisurface.GeneratedPaths(), clisurface.RegenerateCommand))
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
		empty, err := clisurface.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Historic note.\n\n```bash\nbrutus logon --target host:3389 --sticky-keys-exec \"whoami\"\n```\n"
		issues := clisurface.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--sticky-keys-exec", issues[0].Token)
		assert.Equal(t, "brutus logon", issues[0].Command)
		assert.Contains(t, issues[0].String(),
			`docs/example.md:4: --sticky-keys-exec is not a flag of "brutus logon"`)
		assert.Contains(t, issues[0].String(), clisurface.AllowlistPath,
			"the message says how to allow a deliberate mention")
	})

	t.Run("the allowlist suppresses a deliberate mention", func(t *testing.T) {
		allow, err := clisurface.ParseAllowlist("--sticky-keys-exec # renamed to --exec; the rename note names the old flag\n")
		require.NoError(t, err)

		doc := "```bash\nbrutus logon --sticky-keys-exec \"whoami\"\n```\n"
		assert.Empty(t, clisurface.LintMarkdown(documented, "docs/example.md", doc, allow))
	})

	t.Run("the logon family rejects the inherited --timeout", func(t *testing.T) {
		empty, err := clisurface.ParseAllowlist("")
		require.NoError(t, err)

		doc := "```bash\nbrutus logon --target host:3389 --timeout 30s\n```\n"
		issues := clisurface.LintMarkdown(documented, "docs/example.md", doc, empty)

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
