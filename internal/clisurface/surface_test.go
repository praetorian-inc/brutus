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
	"fmt"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTree builds a synthetic command tree that mirrors the shapes the real
// brutus tree has: a root with persistent flags, a leaf with local flags, a
// leaf that rejects an inherited flag from its PreRunE, aliases, a hidden and
// deprecated command, and a group command that is not runnable.
func newTestTree() *cobra.Command {
	root := &cobra.Command{Use: "tool", Short: "a tool", RunE: func(*cobra.Command, []string) error { return nil }}
	root.PersistentFlags().Duration("timeout", 10*time.Second, "per-target timeout")
	root.PersistentFlags().BoolP("json", "j", false, "JSON output")
	root.Flags().Bool("version", false, "show version")

	scan := &cobra.Command{
		Use:     "scan",
		Short:   "scan things",
		Aliases: []string{"sc", "scanner"},
		Example: "  # scan one host\n  tool scan --target host",
		RunE:    func(*cobra.Command, []string) error { return nil },
	}
	scan.Flags().StringP("target", "t", "", "target host:port")

	// guarded mirrors brutus's logon family: it inherits --timeout from the
	// root but its PreRunE hard-errors when the flag is set.
	guarded := &cobra.Command{Use: "guarded", Short: "rejects --timeout", RunE: func(*cobra.Command, []string) error { return nil }}
	guarded.Flags().Duration("scan-timeout", time.Second, "settle deadline")
	guarded.PreRunE = func(c *cobra.Command, _ []string) error {
		if c.Flags().Changed("timeout") {
			return fmt.Errorf("--timeout is not valid here; use --scan-timeout")
		}
		return nil
	}

	group := &cobra.Command{Use: "group", Short: "a group of things"}
	leaf := &cobra.Command{Use: "leaf", Short: "a leaf", RunE: func(*cobra.Command, []string) error { return nil }}
	leaf.Flags().String("only-here", "", "leaf-local flag")
	hidden := &cobra.Command{
		Use:        "old",
		Short:      "the old spelling",
		Hidden:     true,
		Deprecated: `use "tool group leaf" instead`,
		RunE:       func(*cobra.Command, []string) error { return nil },
	}
	group.AddCommand(leaf, hidden)

	root.AddCommand(scan, guarded, group)
	return root
}

func TestWalkCollectsEveryCommandSortedByPath(t *testing.T) {
	s := Walk(newTestTree())

	var paths []string
	for i := range s.Commands {
		paths = append(paths, s.Commands[i].Path)
	}
	assert.Equal(t, []string{
		"tool",
		"tool group",
		"tool group leaf",
		"tool group old",
		"tool guarded",
		"tool scan",
	}, paths, "commands must be collected recursively and sorted by full path")
}

func TestWalkRecordsCommandMetadata(t *testing.T) {
	s := Walk(newTestTree())

	scan, ok := s.Command("tool scan")
	require.True(t, ok, "tool scan must be in the surface")
	assert.Equal(t, "scan", scan.Use)
	assert.Equal(t, "scan things", scan.Short)
	assert.Equal(t, []string{"sc", "scanner"}, scan.Aliases)
	assert.True(t, scan.Runnable, "scan has a RunE so it is runnable")
	assert.False(t, scan.Hidden)
	assert.Contains(t, scan.Example, "tool scan --target host")

	group, ok := s.Command("tool group")
	require.True(t, ok)
	assert.False(t, group.Runnable, "a command with no RunE only groups subcommands")

	old, ok := s.Command("tool group old")
	require.True(t, ok)
	assert.True(t, old.Hidden, "hidden commands stay in the surface so the linter accepts them")
	assert.Equal(t, `use "tool group leaf" instead`, old.Deprecated)
}

func TestWalkSeparatesLocalFromInheritedFlags(t *testing.T) {
	s := Walk(newTestTree())

	scan, ok := s.Command("tool scan")
	require.True(t, ok)

	target, ok := scan.Flag("target")
	require.True(t, ok, "scan must carry its own --target")
	assert.False(t, target.Inherited, "--target is declared on scan")
	assert.Equal(t, "t", target.Shorthand)
	assert.Equal(t, "string", target.Type)

	timeout, ok := scan.Flag("timeout")
	require.True(t, ok, "scan must carry the root-persistent --timeout")
	assert.True(t, timeout.Inherited, "--timeout reaches scan from the root")
	assert.Equal(t, "duration", timeout.Type)
	assert.Equal(t, "10s", timeout.Default)

	_, ok = scan.Flag("version")
	assert.False(t, ok, "--version is local to the root and must not leak into subcommands")

	root, ok := s.Command("tool")
	require.True(t, ok)
	version, ok := root.Flag("version")
	require.True(t, ok)
	assert.False(t, version.Inherited, "the root's own flags are not inherited")
}

func TestWalkSortsFlagsByName(t *testing.T) {
	s := Walk(newTestTree())

	scan, ok := s.Command("tool scan")
	require.True(t, ok)

	var names []string
	for i := range scan.Flags {
		names = append(names, scan.Flags[i].Name)
	}
	assert.Equal(t, []string{"json", "target", "timeout"}, names, "flags must be sorted by name")
}

func TestWalkMarksFlagsTheCommandRejects(t *testing.T) {
	s := Walk(newTestTree())

	guarded, ok := s.Command("tool guarded")
	require.True(t, ok)

	timeout, ok := guarded.Flag("timeout")
	require.True(t, ok, "the rejected flag is still reachable, so it stays in the surface")
	assert.True(t, timeout.Rejected, "PreRunE hard-errors on --timeout, so it is not usable here")
	assert.Equal(t, "--timeout is not valid here; use --scan-timeout", timeout.RejectedReason,
		"the rejection reason is recorded so the generated reference can explain it")

	scanTimeout, ok := guarded.Flag("scan-timeout")
	require.True(t, ok)
	assert.False(t, scanTimeout.Rejected, "the replacement flag is usable")

	json, ok := guarded.Flag("json")
	require.True(t, ok)
	assert.False(t, json.Rejected, "only the guarded flag is rejected, not every inherited flag")

	sibling, ok := s.Command("tool scan")
	require.True(t, ok)
	siblingTimeout, ok := sibling.Flag("timeout")
	require.True(t, ok)
	assert.False(t, siblingTimeout.Rejected, "the rejection is per command, not global")
}

func TestWalkDetectsRejectionEvenWhenAFlagWasAlreadySet(t *testing.T) {
	root := newTestTree()
	guarded, _, err := root.Find([]string{"guarded"})
	require.NoError(t, err)

	// Simulate an earlier test having parsed --timeout on the shared flag.
	require.NoError(t, root.PersistentFlags().Set("timeout", "30s"))
	require.True(t, root.PersistentFlags().Lookup("timeout").Changed)

	s := Walk(root)

	cmd, ok := s.Command("tool guarded")
	require.True(t, ok)
	timeout, ok := cmd.Flag("timeout")
	require.True(t, ok)
	assert.True(t, timeout.Rejected,
		"a Changed bit left set by another test must not hide the rejection")

	assert.True(t, root.PersistentFlags().Lookup("timeout").Changed,
		"the probe must not clear a Changed bit that was already set")
	assert.Equal(t, "30s", root.PersistentFlags().Lookup("timeout").Value.String(),
		"the probe must never touch flag values")
	assert.Nil(t, guarded.Flags().Lookup("timeout"),
		"and it must not merge the ancestor's flag into the command's own FlagSet")
}

// TestWalkDoesNotMutateTheTree pins the invariant that broke once already: a
// cobra tree is package-level state shared by every test in a binary, so a Walk
// that merges persistent flags into a command's own FlagSet makes every later
// test see flags the command does not declare.
func TestWalkDoesNotMutateTheTree(t *testing.T) {
	root := newTestTree()
	scan, _, err := root.Find([]string{"scan"})
	require.NoError(t, err)
	guarded, _, err := root.Find([]string{"guarded"})
	require.NoError(t, err)

	require.Nil(t, scan.Flags().Lookup("timeout"),
		"precondition: the child does not declare the root's persistent flag")
	require.Nil(t, scan.Flags().ShorthandLookup("j"),
		"precondition: the child does not declare the root's persistent shorthand")

	s := Walk(root)

	timeout, ok := mustFlag(t, s, "tool scan", "timeout")
	require.True(t, ok)
	require.True(t, timeout.Inherited, "the surface still records the inherited flag")

	assert.Nil(t, scan.Flags().Lookup("timeout"),
		"Walk must not fold the root's persistent flags into the child's own FlagSet")
	assert.Nil(t, scan.Flags().ShorthandLookup("j"),
		"nor its shorthands, which is what makes a -t collision test start failing")
	assert.Nil(t, guarded.Flags().Lookup("timeout"),
		"not even on a command whose PreRunE the probe had to run")

	for _, name := range []string{"timeout", "json"} {
		assert.False(t, root.PersistentFlags().Lookup(name).Changed,
			"--%s must not be left marked as set by the probe", name)
	}
}

func TestWalkIsIdenticalWhetherTheTreeWasAlreadyMerged(t *testing.T) {
	pristine := Walk(newTestTree())

	merged := newTestTree()
	// InheritedFlags is cobra's mutating accessor: calling it folds the
	// ancestors' persistent flags into each command's own FlagSet, which is the
	// state Walk finds when another test rendered help or executed the tree
	// first.
	forEachCommand(merged, func(c *cobra.Command) { _ = c.InheritedFlags() })
	require.NotNil(t, mustCommand(t, merged, "scan").Flags().Lookup("timeout"),
		"precondition: the tree really is merged now")

	assert.Equal(t, pristine, Walk(merged),
		"flag classification must come from the ancestors' persistent flags, not from whatever is in cmd.Flags()")
	assert.Equal(t, pristine.Hash(), Walk(merged).Hash())
}

func TestWalkIgnoresCommandsWithoutAnAttributableRejection(t *testing.T) {
	root := &cobra.Command{Use: "tool", RunE: func(*cobra.Command, []string) error { return nil }}
	root.PersistentFlags().Bool("json", false, "JSON output")
	always := &cobra.Command{Use: "always", Short: "always fails", RunE: func(*cobra.Command, []string) error { return nil }}
	always.PreRunE = func(*cobra.Command, []string) error { return fmt.Errorf("this command always refuses to run") }
	root.AddCommand(always)

	s := Walk(root)

	cmd, ok := s.Command("tool always")
	require.True(t, ok)
	for i := range cmd.Flags {
		assert.False(t, cmd.Flags[i].Rejected,
			"a PreRunE that fails unconditionally attributes nothing to flag %q", cmd.Flags[i].Name)
	}
}

func TestWalkExcludesCobrasInjectedCommands(t *testing.T) {
	root := newTestTree()
	// Executing a tree is what makes cobra inject help/completion. Whether
	// that happened must not change the surface.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	s := Walk(root)

	_, hasHelp := s.Command("tool help")
	_, hasCompletion := s.Command("tool completion")
	assert.False(t, hasHelp, "cobra's injected help command is not part of the documented surface")
	assert.False(t, hasCompletion, "cobra's injected completion command is not part of the documented surface")
}

func TestWalkIsDeterministic(t *testing.T) {
	first := Walk(newTestTree())
	second := Walk(newTestTree())

	assert.Equal(t, first, second, "two walks of identical trees must produce identical surfaces")
	assert.Equal(t, first.Hash(), second.Hash(), "and identical hashes")

	firstJSON, err := RenderJSON(first)
	require.NoError(t, err)
	secondJSON, err := RenderJSON(second)
	require.NoError(t, err)
	assert.Equal(t, string(firstJSON), string(secondJSON), "rendering must be byte-identical")
}

func TestHashTracksStructureNotProse(t *testing.T) {
	base := Walk(newTestTree())

	renamed := Walk(newTestTree())
	cmd, ok := renamed.Command("tool scan")
	require.True(t, ok)
	flag, ok := cmd.Flag("target")
	require.True(t, ok)
	flag.Name = "host"
	assert.NotEqual(t, base.Hash(), renamed.Hash(), "renaming a flag must move the hash")

	reworded := Walk(newTestTree())
	cmd, ok = reworded.Command("tool scan")
	require.True(t, ok)
	cmd.Short = "scan things, but described differently"
	flag, ok = cmd.Flag("target")
	require.True(t, ok)
	flag.Usage = "reworded usage"
	assert.Equal(t, base.Hash(), reworded.Hash(),
		"the hash pins the structural surface, so rewording help text must not move it")
}

func TestSurfaceLookupHelpers(t *testing.T) {
	s := Walk(newTestTree())

	assert.Equal(t, "tool", s.Root(), "the root is the shortest command path")

	var childPaths []string
	for _, c := range s.Children("tool") {
		childPaths = append(childPaths, c.Path)
	}
	assert.Equal(t, []string{"tool group", "tool guarded", "tool scan"}, childPaths,
		"Children returns direct subcommands only")

	assert.Equal(t, []string{"tool group leaf", "tool group old"},
		pathsOf(s.Children("tool group")))

	_, ok := s.Command("tool nope")
	assert.False(t, ok)

	assert.Equal(t, []string{"json", "only-here", "scan-timeout", "target", "timeout", "version"},
		s.FlagNames(), "FlagNames is the sorted union of every flag in the tree")

	scan, ok := s.Command("tool scan")
	require.True(t, ok)
	byShorthand, ok := scan.FlagByShorthand("t")
	require.True(t, ok)
	assert.Equal(t, "target", byShorthand.Name)
	_, ok = scan.FlagByShorthand("z")
	assert.False(t, ok)
}

func TestSurfaceRootOfEmptySurface(t *testing.T) {
	assert.Empty(t, Surface{}.Root())
}

// pathsOf is a test helper that flattens command pointers to their paths.
func pathsOf(cmds []*Command) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.Path)
	}
	return out
}

// mustFlag looks up one flag of one command in a surface.
func mustFlag(t *testing.T, s Surface, path, name string) (*Flag, bool) {
	t.Helper()
	cmd, ok := s.Command(path)
	require.True(t, ok, "command %q must be in the surface", path)
	return cmd.Flag(name)
}

// mustCommand resolves a command by name from a live cobra tree.
func mustCommand(t *testing.T, root *cobra.Command, name string) *cobra.Command {
	t.Helper()
	cmd, _, err := root.Find([]string{name})
	require.NoError(t, err)
	require.NotNil(t, cmd)
	return cmd
}

// forEachCommand applies fn to every command in the tree.
func forEachCommand(cmd *cobra.Command, fn func(*cobra.Command)) {
	fn(cmd)
	for _, child := range cmd.Commands() {
		forEachCommand(child, fn)
	}
}
