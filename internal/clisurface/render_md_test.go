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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMarkdownDocumentsEveryCommand(t *testing.T) {
	s := Walk(newTestTree())

	md := string(RenderMarkdown(s))

	assert.True(t, strings.HasPrefix(md, generatedNotice), "the file warns that it is generated")
	assert.Contains(t, md, "Do not edit by hand")
	assert.Contains(t, md, "# tool CLI reference")
	assert.Contains(t, md, "surface hash `"+s.Hash()+"`")
	for _, path := range []string{"tool", "tool scan", "tool guarded", "tool group", "tool group leaf", "tool group old"} {
		assert.Contains(t, md, "## `"+path+"`", "every command gets a section")
	}
	assert.Contains(t, md, "| [`tool scan`](#tool-scan) |", "the index links to the sections")
	assert.True(t, strings.HasSuffix(md, "\n"))
}

func TestRenderMarkdownSeparatesLocalInheritedAndRejectedFlags(t *testing.T) {
	s := Walk(newTestTree())

	md := string(RenderMarkdown(s))
	guarded := section(t, md, "tool guarded")

	assert.Contains(t, guarded, "### Flags")
	assert.Contains(t, guarded, "| `--scan-timeout` |")
	assert.Contains(t, guarded, "### Inherited flags")
	assert.Contains(t, guarded, "| `--json` | `-j` | bool |")
	assert.Contains(t, guarded, "### Rejected flags")
	assert.Contains(t, guarded, "| `--timeout` | --timeout is not valid here; use --scan-timeout |")

	timeoutRows := strings.Count(guarded, "`--timeout`")
	assert.Equal(t, 1, timeoutRows,
		"a rejected flag appears only in the rejected table, never as a usable option")
}

func TestRenderMarkdownAnnotatesHiddenAndDeprecatedCommands(t *testing.T) {
	s := Walk(newTestTree())

	md := string(RenderMarkdown(s))
	old := section(t, md, "tool group old")

	assert.Contains(t, old, "- Hidden: not shown in `--help` output")
	assert.Contains(t, old, `- Deprecated: use "tool group leaf" instead`)
	assert.Contains(t, md, "the old spelling (deprecated:", "the index flags it too")
	assert.Contains(t, section(t, md, "tool group"), "- Requires a subcommand")
}

func TestRenderMarkdownIncludesDedentedExamples(t *testing.T) {
	s := Walk(newTestTree())

	scan := section(t, string(RenderMarkdown(s)), "tool scan")

	assert.Contains(t, scan, "### Examples")
	assert.Contains(t, scan, "```bash\n# scan one host\ntool scan --target host\n```",
		"cobra's two-space example indent is removed so the fence is a plain shell block")
}

func TestRenderMarkdownEscapesTableCells(t *testing.T) {
	s := Surface{Commands: []Command{{
		Path: "tool", Use: "tool", Short: "a | b", Runnable: true,
		Flags: []Flag{{Name: "mode", Type: "string", Usage: "cautious | default | aggressive\nsecond line"}},
	}}}

	md := string(RenderMarkdown(s))

	assert.Contains(t, md, `cautious \| default \| aggressive second line`,
		"pipes are escaped and newlines folded so the markdown table survives")
}

func TestRenderRegionsListsSubcommandsWithoutClaimingACount(t *testing.T) {
	s := Walk(newTestTree())

	regions := RenderRegions(s)
	require.Len(t, regions, 2)
	assert.Equal(t, RegionSubcommands, regions[0].Name, "regions render in a fixed order")
	assert.Equal(t, RegionAliases, regions[1].Name)

	body := regions[0].Body
	assert.Contains(t, body, "Brutus organizes its functionality into these focused subcommands:")
	assert.NotRegexp(t, `into \d+ `, body,
		"the list below is the count; a written count is a second thing that can be wrong")
	assert.Contains(t, body, "```bash\ntool group   # a group of things\n")
	assert.Contains(t, body, "tool guarded # rejects --timeout\n")
	assert.Contains(t, body, "tool scan    # scan things\n")
	assert.NotContains(t, body, "tool group leaf", "only top-level subcommands are listed")
}

func TestRenderRegionsAliasTableOmitsCommandsWithoutAliases(t *testing.T) {
	s := Walk(newTestTree())

	body := RenderRegions(s)[1].Body

	assert.Contains(t, body, "| `scan` | `sc`, `scanner` |")
	assert.NotContains(t, body, "*(none)*",
		"the region says 'some subcommands carry aliases', so rows saying 'none' contradict it")
	assert.NotContains(t, body, "| `guarded` |", "a command with no aliases is not listed at all")
	assert.NotContains(t, body, "| `group` |")
	assert.Contains(t, body, "[docs/CLI.md](docs/CLI.md)", "the region links to the full reference")
}

func TestRenderRegionsAliasTableFollowsAliasTransitions(t *testing.T) {
	base := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool scan", Use: "scan", Short: "scan things", Aliases: []string{"sc"}},
		{Path: "tool plain", Use: "plain", Short: "no aliases yet"},
	}}

	body := RenderRegions(base)[1].Body
	require.Contains(t, body, "| `scan` | `sc` |")
	require.NotContains(t, body, "| `plain` |")

	t.Run("a command gaining its first alias appears", func(t *testing.T) {
		gained := base
		gained.Commands = append([]Command(nil), base.Commands...)
		gained.Commands[2].Aliases = []string{"p"}

		body := RenderRegions(gained)[1].Body

		assert.Contains(t, body, "| `plain` | `p` |",
			"declaring an alias must add the command to the README table")
	})

	t.Run("a command losing its last alias disappears", func(t *testing.T) {
		lost := base
		lost.Commands = append([]Command(nil), base.Commands...)
		lost.Commands[1].Aliases = nil

		body := RenderRegions(lost)[1].Body

		assert.NotContains(t, body, "| `scan` |",
			"dropping the last alias must remove the command from the README table")
		assert.Contains(t, body, "[docs/CLI.md](docs/CLI.md)",
			"the rest of the region survives an empty table")
	})
}

func TestRenderRegionsSkipsHiddenSubcommands(t *testing.T) {
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool shown", Use: "shown", Short: "visible"},
		{Path: "tool secret", Use: "secret", Short: "hidden", Hidden: true},
	}}

	body := RenderRegions(s)[0].Body

	assert.Contains(t, body, "tool shown # visible")
	assert.NotContains(t, body, "secret", "hidden commands stay out of the Quick Start listing")
}

func TestUsageIncludesTheArgumentSketch(t *testing.T) {
	assert.Equal(t, "tool scan [flags]", usage(&Command{Path: "tool scan", Use: "scan [flags]"}))
	assert.Equal(t, "tool scan", usage(&Command{Path: "tool scan", Use: "scan"}))
}

func TestDedentLeavesUnindentedTextAlone(t *testing.T) {
	assert.Equal(t, "a\nb", dedent("a\nb"))
	assert.Equal(t, "a\n\nb", dedent("  a\n\n  b"))
}

// section returns the docs/CLI.md section for one command path.
func section(t *testing.T, md, path string) string {
	t.Helper()
	heading := "## `" + path + "`"
	start := strings.Index(md, heading)
	require.GreaterOrEqual(t, start, 0, "section %q must exist", heading)
	rest := md[start+len(heading):]
	if next := strings.Index(rest, "\n## "); next >= 0 {
		return rest[:next]
	}
	return rest
}
