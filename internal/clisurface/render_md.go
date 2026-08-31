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
	"strconv"
	"strings"
)

// generatedNotice heads every generated markdown artifact.
const generatedNotice = "<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->"

// Region names spliced into README.md.
const (
	RegionSubcommands = "cli-subcommands"
	RegionAliases     = "cli-aliases"
)

// Region is one generated block of a hand-written document.
type Region struct {
	Name string
	Body string
}

// RenderMarkdown renders the full human-readable reference (docs/CLI.md).
func RenderMarkdown(s Surface) []byte {
	root := s.Root()

	var b strings.Builder
	writeLines(&b,
		generatedNotice,
		"",
		"# "+root+" CLI reference",
		"",
		"Every command, alias and flag below is derived from the cobra command tree, not from prose.",
		"Schema version "+strconv.Itoa(SchemaVersion)+", surface hash `"+s.Hash()+"`.",
		"",
		"Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.",
		"",
		"## Command index",
		"",
		"| Command | Aliases | Description |",
		"| --- | --- | --- |",
	)
	for i := range s.Commands {
		c := &s.Commands[i]
		writeLines(&b, "| ["+code(c.Path)+"](#"+anchor(c.Path)+") | "+aliasCell(c)+" | "+cell(indexDescription(c))+" |")
	}

	for i := range s.Commands {
		writeCommand(&b, &s.Commands[i])
	}

	return []byte(b.String())
}

// writeCommand renders one command section of the reference.
func writeCommand(b *strings.Builder, c *Command) {
	writeLines(b, "", "## "+code(c.Path), "")
	if c.Short != "" {
		writeLines(b, c.Short, "")
	}

	writeLines(b, "- Usage: "+code(usage(c)))
	writeLines(b, "- Aliases: "+aliasCell(c))
	if c.Hidden {
		writeLines(b, "- Hidden: not shown in `--help` output")
	}
	if c.Deprecated != "" {
		writeLines(b, "- Deprecated: "+c.Deprecated)
	}
	if !c.Runnable {
		writeLines(b, "- Requires a subcommand")
	}

	local, inherited, rejected := partitionFlags(c)
	writeFlagTable(b, "Flags", local)
	writeFlagTable(b, "Inherited flags", inherited)

	if len(rejected) > 0 {
		writeLines(b, "", "### Rejected flags", "",
			"These flags reach "+code(c.Path)+" through inheritance, but the command refuses them:",
			"", "| Flag | Why |", "| --- | --- |")
		for _, f := range rejected {
			writeLines(b, "| "+code("--"+f.Name)+" | "+cell(f.RejectedReason)+" |")
		}
	}

	if c.Example != "" {
		writeLines(b, "", "### Examples", "", "```bash")
		writeLines(b, strings.Split(strings.TrimRight(dedent(c.Example), "\n"), "\n")...)
		writeLines(b, "```")
	}
}

// writeFlagTable renders a titled flag table, or nothing when there are none.
func writeFlagTable(b *strings.Builder, title string, flags []*Flag) {
	if len(flags) == 0 {
		return
	}
	writeLines(b, "", "### "+title, "", "| Flag | Short | Type | Default | Description |", "| --- | --- | --- | --- | --- |")
	for _, f := range flags {
		short := ""
		if f.Shorthand != "" {
			short = code("-" + f.Shorthand)
		}
		def := ""
		if f.Default != "" {
			def = code(f.Default)
		}
		writeLines(b, "| "+code("--"+f.Name)+" | "+short+" | "+f.Type+" | "+def+" | "+cell(flagDescription(f))+" |")
	}
}

// RenderRegions renders the generated regions of README.md, in a fixed order.
func RenderRegions(s Surface) []Region {
	return []Region{
		{Name: RegionSubcommands, Body: renderSubcommandRegion(s)},
		{Name: RegionAliases, Body: renderAliasRegion(s)},
	}
}

// renderSubcommandRegion renders the Quick Start subcommand listing: the
// visible top-level commands with their cobra Short descriptions. It states no
// count — the list below it is the count, and a written one would be a second
// thing that can go stale.
func renderSubcommandRegion(s Surface) string {
	root := s.Root()
	children := visible(s.Children(root))

	width := 0
	for _, c := range children {
		if n := len(name(c.Path)); n > width {
			width = n
		}
	}

	var b strings.Builder
	writeLines(&b,
		"Brutus organizes its functionality into these focused subcommands:",
		"",
		"```bash",
	)
	for _, c := range children {
		writeLines(&b, fmt.Sprintf("%s %-*s # %s", root, width, name(c.Path), c.Short))
	}
	writeLines(&b, "```")
	return b.String()
}

// renderAliasRegion renders the Quick Start alias table. Only subcommands that
// actually declare aliases are listed: this is the most-read part of the
// README, and rows reading "none" contradict the lead-in and add noise.
// docs/CLI.md remains the complete reference and does list them.
func renderAliasRegion(s Surface) string {
	root := s.Root()

	var b strings.Builder
	writeLines(&b,
		"Some subcommands carry aliases for discoverability:",
		"",
		"| Subcommand | Aliases |",
		"| --- | --- |",
	)
	for _, c := range visible(s.Children(root)) {
		if len(c.Aliases) == 0 {
			continue
		}
		writeLines(&b, "| "+code(name(c.Path))+" | "+aliasCell(c)+" |")
	}
	writeLines(&b,
		"",
		"The full reference — every subcommand, alias and flag, including the ones "+
			"hidden from `--help` — is generated into [docs/CLI.md](docs/CLI.md).",
	)
	return b.String()
}

// --- helpers ---------------------------------------------------------------

// writeLines appends each line plus a newline.
func writeLines(b *strings.Builder, lines ...string) {
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
}

// visible drops commands hidden from help output.
func visible(cmds []*Command) []*Command {
	out := make([]*Command, 0, len(cmds))
	for _, c := range cmds {
		if !c.Hidden {
			out = append(out, c)
		}
	}
	return out
}

// partitionFlags splits a command's flags into the ones declared on it, the
// usable ones it inherits, and the ones it inherits but refuses.
func partitionFlags(c *Command) (local, inherited, rejected []*Flag) {
	for i := range c.Flags {
		f := &c.Flags[i]
		switch {
		case f.Rejected:
			rejected = append(rejected, f)
		case f.Inherited:
			inherited = append(inherited, f)
		default:
			local = append(local, f)
		}
	}
	return local, inherited, rejected
}

// name returns the last segment of a command path.
func name(path string) string {
	if i := strings.LastIndex(path, " "); i >= 0 {
		return path[i+1:]
	}
	return path
}

// usage renders the invocation sketch: the full path with the cobra Use
// string's argument sketch (everything after the command name) appended.
func usage(c *Command) string {
	if i := strings.Index(c.Use, " "); i >= 0 {
		return c.Path + c.Use[i:]
	}
	return c.Path
}

// indexDescription is the command-index description, annotated for commands
// that are hidden or deprecated.
func indexDescription(c *Command) string {
	switch {
	case c.Deprecated != "":
		return c.Short + " (deprecated: " + c.Deprecated + ")"
	case c.Hidden:
		return c.Short + " (hidden)"
	default:
		return c.Short
	}
}

// flagDescription is the flag-table description, annotated for flags that are
// hidden or deprecated.
func flagDescription(f *Flag) string {
	switch {
	case f.Deprecated != "":
		return f.Usage + " (deprecated: " + f.Deprecated + ")"
	case f.Hidden:
		return f.Usage + " (hidden)"
	default:
		return f.Usage
	}
}

// aliasCell renders a command's aliases for a table cell.
func aliasCell(c *Command) string {
	if len(c.Aliases) == 0 {
		return "*(none)*"
	}
	out := make([]string, 0, len(c.Aliases))
	for _, a := range c.Aliases {
		out = append(out, code(a))
	}
	return strings.Join(out, ", ")
}

// code wraps s in markdown code ticks.
func code(s string) string { return "`" + s + "`" }

// cell makes arbitrary help text safe inside a markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

// anchor is the GitHub heading anchor for a "## `path`" heading.
func anchor(path string) string {
	return strings.ReplaceAll(path, " ", "-")
}

// dedent removes the common leading-space indent cobra examples carry so the
// rendered fence is not indented as a code block twice over.
func dedent(s string) string {
	lines := strings.Split(s, "\n")
	indent := -1
	for _, l := range lines {
		trimmed := strings.TrimLeft(l, " ")
		if trimmed == "" {
			continue
		}
		if n := len(l) - len(trimmed); indent < 0 || n < indent {
			indent = n
		}
	}
	if indent <= 0 {
		return s
	}
	for i, l := range lines {
		if len(l) >= indent {
			lines[i] = l[indent:]
		} else {
			lines[i] = strings.TrimLeft(l, " ")
		}
	}
	return strings.Join(lines, "\n")
}
