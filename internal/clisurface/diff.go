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
	"sort"
	"strconv"
	"strings"
)

// FindingKind classifies a single disagreement between the documented surface
// and the surface cobra actually registers.
type FindingKind string

const (
	// CommandUndocumented: cobra registers a command the docs do not describe.
	CommandUndocumented FindingKind = "command-undocumented"
	// CommandRemoved: the docs describe a command cobra no longer registers.
	CommandRemoved FindingKind = "command-removed"
	// CommandChanged: a documented command's metadata drifted.
	CommandChanged FindingKind = "command-changed"
	// FlagUndocumented: cobra registers a flag the docs do not describe.
	FlagUndocumented FindingKind = "flag-undocumented"
	// FlagRemoved: the docs describe a flag cobra no longer accepts.
	FlagRemoved FindingKind = "flag-removed"
	// FlagChanged: a documented flag's metadata drifted.
	FlagChanged FindingKind = "flag-changed"
)

// Finding is one actionable disagreement. It always names the command, names
// the flag when the disagreement is about a flag, and says what changed.
type Finding struct {
	Kind FindingKind
	// Command is the full command path, e.g. "brutus logon".
	Command string
	// Flag is the long flag name without dashes, empty for command findings.
	Flag string
	// Field is the metadata field that drifted, empty for add/remove findings.
	Field string
	// Documented is the value in the committed docs.
	Documented string
	// Registered is the value cobra registers.
	Registered string
}

// String renders the finding as one actionable line.
func (f Finding) String() string {
	subject := strconv.Quote(f.Command)
	if f.Flag != "" {
		subject = "flag --" + f.Flag + " on " + strconv.Quote(f.Command)
	}
	switch f.Kind {
	case CommandUndocumented:
		return "command " + subject + " is registered by cobra but missing from the generated docs"
	case CommandRemoved:
		return "command " + subject + " is in the generated docs but cobra no longer registers it"
	case FlagUndocumented:
		return subject + " is registered by cobra but missing from the generated docs"
	case FlagRemoved:
		return subject + " is in the generated docs but cobra no longer accepts it"
	case CommandChanged, FlagChanged:
		return subject + ": " + f.Field + " changed from " + strconv.Quote(f.Documented) +
			" (docs) to " + strconv.Quote(f.Registered) + " (cobra)"
	default:
		return string(f.Kind) + ": " + subject
	}
}

// Diff compares the documented surface against the surface cobra registers and
// returns one finding per disagreement, ordered by command path then flag name.
// It is deliberately not a text diff: every finding names what changed so the
// failure explains itself without the reader diffing two files by eye.
func Diff(documented, registered Surface) []Finding {
	var findings []Finding

	for i := range registered.Commands {
		live := &registered.Commands[i]
		doc, ok := documented.Command(live.Path)
		if !ok {
			findings = append(findings, Finding{Kind: CommandUndocumented, Command: live.Path})
			continue
		}
		findings = append(findings, diffCommand(doc, live)...)
	}

	for i := range documented.Commands {
		doc := &documented.Commands[i]
		if _, ok := registered.Command(doc.Path); !ok {
			findings = append(findings, Finding{Kind: CommandRemoved, Command: doc.Path})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Command != findings[j].Command {
			return findings[i].Command < findings[j].Command
		}
		return findings[i].Flag < findings[j].Flag
	})
	return findings
}

// diffCommand compares one command's metadata and flag set.
func diffCommand(doc, live *Command) []Finding {
	var findings []Finding

	changed := func(field, documented, registered string) {
		if documented != registered {
			findings = append(findings, Finding{
				Kind: CommandChanged, Command: live.Path, Field: field,
				Documented: documented, Registered: registered,
			})
		}
	}
	changed("use", doc.Use, live.Use)
	changed("short description", doc.Short, live.Short)
	changed("aliases", strings.Join(doc.Aliases, ","), strings.Join(live.Aliases, ","))
	changed("hidden", strconv.FormatBool(doc.Hidden), strconv.FormatBool(live.Hidden))
	changed("deprecation notice", doc.Deprecated, live.Deprecated)
	changed("runnable", strconv.FormatBool(doc.Runnable), strconv.FormatBool(live.Runnable))
	changed("example", doc.Example, live.Example)

	for i := range live.Flags {
		lf := &live.Flags[i]
		df, ok := doc.Flag(lf.Name)
		if !ok {
			findings = append(findings, Finding{Kind: FlagUndocumented, Command: live.Path, Flag: lf.Name})
			continue
		}
		findings = append(findings, diffFlag(live.Path, df, lf)...)
	}
	for i := range doc.Flags {
		df := &doc.Flags[i]
		if _, ok := live.Flag(df.Name); !ok {
			findings = append(findings, Finding{Kind: FlagRemoved, Command: live.Path, Flag: df.Name})
		}
	}
	return findings
}

// diffFlag compares one flag's metadata on one command.
func diffFlag(path string, doc, live *Flag) []Finding {
	var findings []Finding
	changed := func(field, documented, registered string) {
		if documented != registered {
			findings = append(findings, Finding{
				Kind: FlagChanged, Command: path, Flag: live.Name, Field: field,
				Documented: documented, Registered: registered,
			})
		}
	}
	changed("shorthand", doc.Shorthand, live.Shorthand)
	changed("type", doc.Type, live.Type)
	changed("default", doc.Default, live.Default)
	changed("usage", doc.Usage, live.Usage)
	changed("deprecation notice", doc.Deprecated, live.Deprecated)
	changed("inherited", strconv.FormatBool(doc.Inherited), strconv.FormatBool(live.Inherited))
	changed("hidden", strconv.FormatBool(doc.Hidden), strconv.FormatBool(live.Hidden))
	changed("rejected by the command", strconv.FormatBool(doc.Rejected), strconv.FormatBool(live.Rejected))
	changed("rejection reason", doc.RejectedReason, live.RejectedReason)
	return findings
}

// Report renders findings as a failure message that says what drifted, which
// files carry the stale copy, and the one command that fixes them.
func Report(findings []Finding, artifacts []string, regenerate string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CLI surface drift: %d disagreement(s) between the generated documentation and the cobra command tree.\n\n",
		len(findings))
	for i := range findings {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, findings[i].String())
	}
	// One trailer, not one per finding: the remediation is the same for all of them,
	// and repeating it buries the findings it is meant to explain.
	fmt.Fprintf(&b, "\nRegenerate %s with '%s'.\n", strings.Join(artifacts, ", "), regenerate)
	return strings.TrimRight(b.String(), "\n")
}
