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

// Package clisurface derives the documented CLI surface of a cobra command
// tree — every command, alias and flag — from the live tree rather than from
// prose, renders it into machine- and human-readable artifacts, and reports
// structured findings when the committed artifacts disagree with the tree.
package clisurface

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// SchemaVersion is the version of the JSON artifact layout. Bump it when the
// shape of the rendered JSON changes in a way consumers must notice.
const SchemaVersion = 1

// builtinCommands are the commands cobra injects into a tree on the first
// Execute (InitDefaultHelpCmd / InitDefaultCompletionCmd). They are not part of
// the surface brutus documents, and whether they are present depends on whether
// something already executed the tree in this process — so excluding them keeps
// the walk deterministic regardless of test ordering.
var builtinCommands = map[string]bool{
	"help":                          true,
	"completion":                    true,
	cobra.ShellCompRequestCmd:       true,
	cobra.ShellCompNoDescRequestCmd: true,
}

// HelpFlag is the flag cobra injects into every command on the first Execute
// (InitDefaultHelpFlag). Like the built-in commands it is excluded from the
// surface — whether it is registered yet depends on whether something already
// executed the tree in this process — and the doc linter accepts it everywhere
// instead (see vocabulary).
const HelpFlag = "help"

// Surface is the complete CLI surface of a command tree. Commands are sorted by
// path and each command's flags are sorted by name, so a Surface renders
// byte-identically across runs.
type Surface struct {
	Commands []Command `json:"commands"`
}

// Command is one node of the command tree.
type Command struct {
	// Path is the full invocation path, e.g. "brutus enum active teams auth".
	Path string `json:"path"`
	// Use is the cobra Use string (the command name plus any argument sketch).
	Use string `json:"use"`
	// Short is the one-line description cobra shows in listings.
	Short string `json:"short"`
	// Aliases are the alternative names that resolve to this command.
	Aliases []string `json:"aliases,omitempty"`
	// Hidden reports whether the command is omitted from help output.
	Hidden bool `json:"hidden,omitempty"`
	// Deprecated is cobra's deprecation notice, empty when not deprecated.
	Deprecated string `json:"deprecated,omitempty"`
	// Runnable reports whether the command does work itself (as opposed to
	// only grouping subcommands).
	Runnable bool `json:"runnable"`
	// Example is cobra's example block, used verbatim in the generated
	// reference. It is part of the surface because it is documentation that
	// must stay honest about the flags it shows.
	Example string `json:"example,omitempty"`
	// Flags are every flag usable on this command: its own, plus the
	// persistent flags inherited from its ancestors.
	Flags []Flag `json:"flags,omitempty"`
}

// Flag is one flag as it appears on one command. The same flag name can appear
// on many commands with different Inherited/Rejected values.
type Flag struct {
	Name       string `json:"name"`
	Shorthand  string `json:"shorthand,omitempty"`
	Type       string `json:"type"`
	Default    string `json:"default,omitempty"`
	Usage      string `json:"usage,omitempty"`
	Deprecated string `json:"deprecated,omitempty"`
	// Inherited reports whether the flag reaches this command as a persistent
	// flag of an ancestor rather than being declared on the command itself.
	Inherited bool `json:"inherited,omitempty"`
	// Hidden reports whether the flag is omitted from help output.
	Hidden bool `json:"hidden,omitempty"`
	// Rejected reports whether the command hard-errors when the flag is set,
	// even though the flag is reachable from the command's flag set. brutus
	// uses this for the logon family, which inherits the root-persistent
	// --timeout but refuses it in favor of --scan-timeout. A flag that is
	// rejected is not usable on the command: the generated reference must not
	// present it as an option and the doc linter must reject examples using it.
	Rejected bool `json:"rejected,omitempty"`
	// RejectedReason is the error the command returns when the flag is set.
	RejectedReason string `json:"rejectedReason,omitempty"`
}

// Walk derives the surface of the tree rooted at root.
//
// Inherited flags are recorded per command, because inheritance alone does not
// make a flag usable: a command's PreRunE may reject a flag it inherits. Walk
// discovers those rejections by probing PreRunE (see probeRejections) rather
// than from a hand-maintained table, so removing the guard in the command
// changes the surface and reddens the gate.
//
// Walk does not mutate the observable tree. That is a hard requirement, not a
// nicety: a cobra tree is usually a package-level variable shared by every test
// in a binary, so any mutation leaks into whatever runs next. In particular Walk
// never calls cobra's LocalFlags or InheritedFlags accessors — both call
// mergePersistentFlags, which permanently folds every ancestor's persistent
// flags into the command's own FlagSet — and it never flips a Changed bit on a
// real flag (see resolveFlags and probeRejections).
//
// One cobra-internal write is unavoidable and harmless: cmd.Commands() sorts a
// command's child slice in place when cobra.EnableCommandSorting is set (the
// default), which is the only way to enumerate children. It is the same sort
// cobra performs itself before printing help, it is idempotent, and the slice is
// unexported — every route to it calls Commands() and therefore sorts first — so
// no caller can observe the difference. Toggling the package-level
// EnableCommandSorting to avoid it would be a data race with any parallel test.
//
// Only PreRunE is probed. A guard implemented in PersistentPreRunE or in RunE
// is not visible to Walk.
func Walk(root *cobra.Command) Surface {
	var s Surface
	collect(root, &s)
	sort.Slice(s.Commands, func(i, j int) bool { return s.Commands[i].Path < s.Commands[j].Path })
	return s
}

// collect appends cmd and its descendants to s, skipping cobra's built-ins.
func collect(cmd *cobra.Command, s *Surface) {
	if builtinCommands[cmd.Name()] {
		return
	}

	s.Commands = append(s.Commands, describe(cmd))

	children := cmd.Commands()
	for i := range children {
		collect(children[i], s)
	}
}

// describe snapshots a single command.
func describe(cmd *cobra.Command) Command {
	out := Command{
		Path:       cmd.CommandPath(),
		Use:        cmd.Use,
		Short:      cmd.Short,
		Aliases:    append([]string(nil), cmd.Aliases...),
		Hidden:     cmd.Hidden,
		Deprecated: cmd.Deprecated,
		Runnable:   cmd.Runnable(),
		Example:    cmd.Example,
	}

	resolved := resolveFlags(cmd)
	out.Flags = make([]Flag, 0, len(resolved))
	for i := range resolved {
		f := resolved[i].flag
		out.Flags = append(out.Flags, Flag{
			Name:       f.Name,
			Shorthand:  f.Shorthand,
			Type:       f.Value.Type(),
			Default:    f.DefValue,
			Usage:      f.Usage,
			Deprecated: f.Deprecated,
			Inherited:  resolved[i].inherited,
			Hidden:     f.Hidden,
		})
	}

	rejected := probeRejections(cmd, resolved)
	for i := range out.Flags {
		if reason, ok := rejected[out.Flags[i].Name]; ok {
			out.Flags[i].Rejected = true
			out.Flags[i].RejectedReason = reason
		}
	}

	return out
}

// resolvedFlag is one flag reachable from a command, and whether the command
// gets it from an ancestor rather than declaring it itself.
type resolvedFlag struct {
	flag      *pflag.Flag
	inherited bool
}

// resolveFlags returns every flag usable on cmd — the flags it declares itself,
// its own persistent flags, and its ancestors' persistent flags — sorted by
// name.
//
// It reads only cobra's non-mutating accessors (Flags, PersistentFlags,
// Parent), so it leaves the tree exactly as it found it. Classification comes
// from the ancestors' persistent-flag names rather than from what happens to be
// in cmd.Flags(), which makes the result identical whether or not something
// else already merged the tree.
func resolveFlags(cmd *cobra.Command) []resolvedFlag {
	inherited := map[string]bool{}
	for parent := cmd.Parent(); parent != nil; parent = parent.Parent() {
		parent.PersistentFlags().VisitAll(func(f *pflag.Flag) { inherited[f.Name] = true })
	}

	var out []resolvedFlag
	seen := map[string]bool{}
	visit := func(f *pflag.Flag) {
		if seen[f.Name] || f.Name == HelpFlag {
			return
		}
		seen[f.Name] = true
		out = append(out, resolvedFlag{flag: f, inherited: inherited[f.Name]})
	}

	cmd.Flags().VisitAll(visit)
	cmd.PersistentFlags().VisitAll(visit)
	for parent := cmd.Parent(); parent != nil; parent = parent.Parent() {
		parent.PersistentFlags().VisitAll(visit)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].flag.Name < out[j].flag.Name })
	return out
}

// probeRejections reports which of the resolved flags cmd's PreRunE refuses,
// keyed by flag name with the error text as the value.
//
// The probe runs PreRunE against a shadow command holding copies of the flags,
// one copy marked as set at a time. A guard reads the command it is handed
// (cobra passes the command being executed), so the shadow is what it inspects
// — and because the Changed bits being flipped belong to copies, the real tree
// is never written to at all. Two guards keep the result trustworthy:
//
//   - Every copy starts with Changed cleared, so a flag another test left
//     marked as set cannot make the baseline fail and silently drop the probe.
//   - The baseline (no flag set) must pass. A PreRunE that fails
//     unconditionally tells us nothing about individual flags, so nothing is
//     reported.
//
// The copies are shallow, so a copy shares the real flag's pflag.Value pointer.
// Only Changed is written, which lives in the copy — but a future guard that
// called Set on a flag would write through to the live tree. A guard that reads
// its inputs is the contract here; see the recover below for the other half.
//
// Probing calls PreRunE outside cobra's execution lifecycle, so a guard that
// assumed cobra had already validated Args and dereferenced args[0] would panic
// and take the whole gate down. That is recovered rather than propagated: an
// unprobeable command yields no rejections, which is the same conservative
// answer as a command with no PreRunE at all, and the deterministic half of the
// gate still covers it.
func probeRejections(cmd *cobra.Command, resolved []resolvedFlag) (rejections map[string]string) {
	if cmd.PreRunE == nil {
		return nil
	}

	defer func() {
		if recover() != nil {
			rejections = nil
		}
	}()

	shadow := &cobra.Command{Use: cmd.Name()}
	copies := make([]*pflag.Flag, 0, len(resolved))
	for i := range resolved {
		duplicate := *resolved[i].flag
		duplicate.Changed = false
		// The struct copy shares the real flag's Value, so a guard calling Set would
		// write straight through to the live tree. frozenValue makes that a no-op
		// while still reporting the real value to anything that reads it.
		duplicate.Value = frozenValue{duplicate.Value}
		// Drop the shorthand. The probe only needs the flag reachable by name, and a
		// command declaring a local flag whose shorthand matches an inherited one
		// would otherwise make pflag panic on the duplicate -- silently aborting the
		// probe via the recover above, and only when the tree had not been merged yet.
		duplicate.Shorthand = ""
		copies = append(copies, &duplicate)
		shadow.Flags().AddFlag(&duplicate)
	}

	if err := cmd.PreRunE(shadow, nil); err != nil {
		return nil
	}

	out := map[string]string{}
	for _, f := range copies {
		f.Changed = true
		err := cmd.PreRunE(shadow, nil)
		f.Changed = false
		if err == nil {
			continue
		}
		out[f.Name] = err.Error()
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// frozenValue is a pflag.Value that reports the real value but refuses to change it,
// so probing a command's PreRunE cannot write to the tree being described.
type frozenValue struct {
	pflag.Value
}

// Set discards the write. A guard that normalises a flag rather than only reading it
// would otherwise mutate the live tree during a walk.
func (frozenValue) Set(string) error { return nil }

// Hash is a stable fingerprint of the structural surface: command paths, names,
// aliases, visibility, and each flag's name, shorthand, type, default and
// usability. Descriptive prose (Short, Usage, Example) is deliberately excluded
// so that rewording help text does not move a hash downstream consumers pin.
func (s Surface) Hash() string {
	lines := make([]string, 0, len(s.Commands)*4)
	for i := range s.Commands {
		c := &s.Commands[i]
		lines = append(lines, strings.Join([]string{
			"command", c.Path, c.Use, strings.Join(c.Aliases, ","),
			strconv.FormatBool(c.Hidden), strconv.FormatBool(c.Runnable), c.Deprecated,
		}, "\t"))
		for j := range c.Flags {
			f := &c.Flags[j]
			lines = append(lines, strings.Join([]string{
				"flag", c.Path, f.Name, f.Shorthand, f.Type, f.Default,
				strconv.FormatBool(f.Inherited), strconv.FormatBool(f.Hidden),
				strconv.FormatBool(f.Rejected), f.Deprecated,
			}, "\t"))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Command returns the command at the given full path.
func (s Surface) Command(path string) (*Command, bool) {
	for i := range s.Commands {
		if s.Commands[i].Path == path {
			return &s.Commands[i], true
		}
	}
	return nil, false
}

// Children returns the direct subcommands of path, in path order.
func (s Surface) Children(path string) []*Command {
	prefix := path + " "
	var out []*Command
	for i := range s.Commands {
		p := s.Commands[i].Path
		if strings.HasPrefix(p, prefix) && !strings.Contains(p[len(prefix):], " ") {
			out = append(out, &s.Commands[i])
		}
	}
	return out
}

// Root returns the shortest command path in the surface, i.e. the binary name.
func (s Surface) Root() string {
	if len(s.Commands) == 0 {
		return ""
	}
	root := s.Commands[0].Path
	for i := range s.Commands {
		if len(s.Commands[i].Path) < len(root) {
			root = s.Commands[i].Path
		}
	}
	return root
}

// Flag returns the named flag as it applies to the command at path.
func (c *Command) Flag(name string) (*Flag, bool) {
	for i := range c.Flags {
		if c.Flags[i].Name == name {
			return &c.Flags[i], true
		}
	}
	return nil, false
}

// FlagByShorthand returns the flag carrying the single-character shorthand.
func (c *Command) FlagByShorthand(short string) (*Flag, bool) {
	for i := range c.Flags {
		if c.Flags[i].Shorthand != "" && c.Flags[i].Shorthand == short {
			return &c.Flags[i], true
		}
	}
	return nil, false
}

// FlagNames returns every long flag name that appears anywhere in the surface.
func (s Surface) FlagNames() []string {
	seen := map[string]bool{}
	var out []string
	for i := range s.Commands {
		c := &s.Commands[i]
		for j := range c.Flags {
			if name := c.Flags[j].Name; !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
