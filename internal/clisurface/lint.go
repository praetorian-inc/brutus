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
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// AllowlistPath is the repo-relative file listing flag names documentation may
// mention even though the CLI does not (or no longer does) accept them.
const AllowlistPath = "docs/cli-surface-allow.txt"

// longFlagPattern matches a long flag token in prose or in a Go comment.
// Group 2 is the token. The leading group requires the dashes to start a word,
// so neither "// -----" rule comments, nor "--" used as a dash-dash separator,
// nor "dash--dash" inside a word can look like a flag.
var longFlagPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_])(--[a-zA-Z0-9][a-zA-Z0-9._-]*)`)

// backtickPattern matches an inline code span on a single line.
var backtickPattern = regexp.MustCompile("`[^`\n]+`")

// Issue is one documentation reference to a flag or subcommand that the CLI
// does not accept.
type Issue struct {
	// File is the repo-relative file the reference appears in.
	File string
	// Line is the 1-based line the reference appears on.
	Line int
	// Token is the offending token exactly as written, dashes included. No
	// example of a removed flag is given here: this package's own comments are
	// linted, and allowlisting a real removed flag to quote it would suppress
	// that name everywhere, including in the README the gate exists to police.
	Token string
	// Command is the command the token was checked against, empty when the
	// token was checked against the whole surface (prose and Go comments).
	Command string
	// Reason says what is wrong.
	Reason string
	// Suggestion is the nearest real flag or subcommand, empty when nothing is
	// close.
	Suggestion string
	// Subcommand reports whether Token is a subcommand name rather than a flag.
	// The two get different advice: the allowlist only holds flag tokens (see
	// ParseAllowlist), so offering it for a misspelled subcommand would send the
	// reader to write an entry the allowlist parser rejects.
	Subcommand bool
}

// String renders the issue as one actionable line.
func (i Issue) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:%d: %s %s", i.File, i.Line, i.Token, i.Reason)
	if i.Command != "" {
		// Every command-scoped reason ends in a preposition, so the command
		// reads as part of the sentence: `--exec is not a flag of "brutus logon"`.
		fmt.Fprintf(&b, " %s", strconv.Quote(i.Command))
	}
	if i.Suggestion != "" {
		label := "nearest real flag"
		if i.Subcommand {
			label = "nearest subcommand"
		}
		fmt.Fprintf(&b, "; %s: %s", label, i.Suggestion)
	}
	// An issue inside a generated file is a symptom of a stale artifact, not
	// something to hand-edit or allowlist: say so, or the reader "fixes" a file
	// the next regeneration overwrites.
	if whollyGenerated(i.File) {
		fmt.Fprintf(&b, ". %s is generated: regenerate it with '%s' rather than editing it",
			i.File, RegenerateCommand)
		return b.String()
	}
	if i.Subcommand {
		fmt.Fprintf(&b, ". Fix the documentation: %s holds flag tokens only", AllowlistPath)
		return b.String()
	}
	fmt.Fprintf(&b, ". Fix the documentation, or add %s to %s with a '#' reason if the mention is deliberate",
		i.Token, AllowlistPath)
	return b.String()
}

// whollyGenerated reports whether every line of path is generated, and so must
// never be hand-edited. README.md is deliberately excluded: only two regions of
// it are generated, so a lint hit there is normally in hand-written prose.
func whollyGenerated(path string) bool {
	return path == JSONPath || path == MarkdownPath
}

// Allowlist holds deliberately documented tokens and why each is allowed.
type Allowlist struct {
	reasons map[string]string
}

// ParseAllowlist reads an allowlist file. Every entry is one token
// ("--<flag>" or "-<x>") followed by a '#' comment giving the reason; blank lines
// and whole-line comments are ignored. The reason is mandatory: an entry
// without one is an error, because an unexplained exception is how a stale
// reference survives forever.
func ParseAllowlist(content string) (Allowlist, error) {
	out := Allowlist{reasons: map[string]string{}}
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, reason, found := strings.Cut(line, "#")
		entry = strings.TrimSpace(entry)
		reason = strings.TrimSpace(reason)
		switch {
		case !strings.HasPrefix(entry, "-"):
			return Allowlist{}, fmt.Errorf("%s:%d: entry %q must start with '-'", AllowlistPath, i+1, entry)
		case !found || reason == "":
			return Allowlist{}, fmt.Errorf("%s:%d: entry %q needs a '# reason' explaining why it is allowed", AllowlistPath, i+1, entry)
		}
		out.reasons[entry] = reason
	}
	return out, nil
}

// Allows reports whether the token is allowlisted.
func (a Allowlist) Allows(entry string) bool {
	_, ok := a.reasons[entry]
	return ok
}

// Entries returns the allowlisted tokens in sorted order.
func (a Allowlist) Entries() []string {
	out := make([]string, 0, len(a.reasons))
	for entry := range a.reasons {
		out = append(out, entry)
	}
	sort.Strings(out)
	return out
}

// LintMarkdown checks one markdown document against the surface.
//
// Fenced code blocks are parsed as shell: line continuations are joined,
// pipelines are split, and only segments whose argv[0] is the CLI binary are
// checked — every flag of every other tool in an example pipeline is ignored,
// which is what keeps the false-positive rate at zero. Prose outside fences is
// checked more loosely: only backticked long-flag tokens, and only against the
// union of every flag in the tree, because prose rarely says which command it
// means.
//
// The argv[0] rule is what buys the zero false-positive rate, and it costs
// reach: an invocation the binary does not lead — "sudo brutus …", "time brutus
// …", "FOO=bar brutus …" — is skipped rather than checked. Recognizing prefixes
// one at a time would trade a guarantee for a list that is never finished, so
// examples are written with the binary first. There are none of the other shape
// in this repository.
func LintMarkdown(s Surface, file, content string, allow Allowlist) []Issue {
	var issues []Issue

	var (
		inFence    bool
		fence      string
		pending    string
		pendingAt  int
		flushFence = func() {
			if pending == "" {
				return
			}
			issues = append(issues, lintShellLine(s, file, pendingAt, pending, allow)...)
			pending = ""
		}
	)

	for i, raw := range strings.Split(content, "\n") {
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)

		if !inFence {
			if delim := fenceDelimiter(trimmed); delim != "" {
				inFence, fence = true, delim
				continue
			}
			issues = append(issues, lintProseLine(s, file, lineNo, raw, allow)...)
			continue
		}

		if isFenceClose(trimmed, fence) {
			flushFence()
			inFence, fence = false, ""
			continue
		}

		body := strings.TrimRight(raw, " \t")
		if pending == "" {
			pendingAt = lineNo
		}
		if strings.HasSuffix(body, `\`) {
			pending += strings.TrimSuffix(body, `\`) + " "
			continue
		}
		pending += body
		flushFence()
	}
	flushFence()

	return issues
}

// fenceDelimiter returns the fence delimiter a line opens a code block with, or
// "" when the line does not open one.
func fenceDelimiter(trimmed string) string {
	for _, delim := range []string{"```", "~~~"} {
		if strings.HasPrefix(trimmed, delim) {
			return delim
		}
	}
	return ""
}

// isFenceClose reports whether the line closes the open fence.
func isFenceClose(trimmed, fence string) bool {
	return strings.HasPrefix(trimmed, fence) && strings.TrimRight(strings.TrimPrefix(trimmed, fence), fence) == ""
}

// lintProseLine checks the backticked long-flag tokens of one prose line
// against the union of every flag in the tree.
func lintProseLine(s Surface, file string, line int, raw string, allow Allowlist) []Issue {
	var issues []Issue
	known := vocabulary(s)
	for _, span := range backtickPattern.FindAllString(raw, -1) {
		for _, tok := range longFlagTokens(span) {
			name := strings.TrimPrefix(tok, "--")
			if allow.Allows(tok) || contains(known, name) {
				continue
			}
			issues = append(issues, Issue{
				File:       file,
				Line:       line,
				Token:      tok,
				Reason:     "is not a flag of any command in the CLI",
				Suggestion: nearest(name, known),
			})
		}
	}
	return issues
}

// lintShellLine checks one logical shell line from a fenced code block.
func lintShellLine(s Surface, file string, line int, text string, allow Allowlist) []Issue {
	var issues []Issue
	root := s.Root()
	for _, argv := range shellSegments(text) {
		if len(argv) == 0 || baseName(argv[0]) != root {
			continue
		}
		issues = append(issues, lintInvocation(s, file, line, argv, allow)...)
	}
	return issues
}

// lintInvocation checks one "brutus ..." invocation.
//
// It works in the two stages cobra works in. First it resolves the command,
// stepping over flags and the values they consume; then it validates every flag
// in the invocation against the command that was finally resolved. That order is
// not incidental — cobra dispatches to the resolved command and parses the whole
// argv against *that* command's flag set, so where a flag sits relative to the
// subcommand does not change whether it is accepted.
//
// Validating each flag against whichever command happened to be resolved when it
// was read gets this wrong in both directions:
//
//   - Reporting a flag against the root because it was written before the
//     subcommand. `brutus --json enum apollo --domain example.com` is legal, but
//     --domain would be reported as not existing on "brutus".
//   - Missing a flag the resolved command refuses. `brutus --timeout 5s logon`
//     fails at runtime because the logon family rejects the inherited --timeout,
//     and `brutus --version logon` fails because --version is local to the root
//     — neither is excused by being written early.
//
// Values are stepped over using the command resolved so far, which is what cobra
// does too: a non-boolean flag takes the next argument, a value-taking shorthand
// takes the rest of its token ("-oresults.json") or the next argument, and "--"
// ends flag parsing. Reading a value as a flag would report its characters as
// nonexistent shorthands.
func lintInvocation(s Surface, file string, line int, argv []string, allow Allowlist) []Issue {
	cmd, ok := s.Command(s.Root())
	if !ok {
		return nil
	}

	var (
		issues []Issue
		flags  []string
	)

	// resolving stays true across flags and goes false at the first positional
	// that is not a subcommand: from there on argv holds this command's
	// arguments, and an argument that happens to spell a subcommand name is not
	// one.
	resolving := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}

		switch {
		case arg == "--":
			// pflag stops parsing here: everything after is positional,
			// however much it looks like a flag.
			i = len(argv)
		case arg == "-":
			// A bare "-" is a positional, conventionally stdin.
			resolving = false
		case strings.HasPrefix(arg, "--"):
			flags = append(flags, arg)
			if longFlagTakesNext(cmd, arg, next) {
				i++
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			flags = append(flags, arg)
			if shortFlagTakesNext(cmd, arg, next) {
				i++
			}
		case resolving:
			child := resolveChild(s, cmd.Path, arg)
			switch {
			case child != nil:
				cmd = child
			case len(s.Children(cmd.Path)) > 0:
				issues = append(issues, Issue{
					File: file, Line: line, Token: arg, Command: cmd.Path,
					Reason:     "is not a subcommand of",
					Suggestion: nearestCommand(s, cmd.Path, arg),
					Subcommand: true,
				})
				resolving = false
			default:
				resolving = false
			}
		}
	}

	for _, arg := range flags {
		if strings.HasPrefix(arg, "--") {
			issues = append(issues, checkLongFlag(s, cmd, file, line, arg, allow)...)
			continue
		}
		issues = append(issues, checkShortFlags(cmd, file, line, arg, allow)...)
	}
	return issues
}

// longFlagTakesNext reports whether the argument after a "--<name>" token is
// that flag's value rather than a token of its own.
//
// A "--<name>=<value>" token carries its own value. Otherwise any non-boolean
// flag takes the next argument. A flag cmd does not declare is guessed from
// shape — anything that does not itself look like a flag — so that one unknown
// flag does not also get its value read as a bogus subcommand.
func longFlagTakesNext(cmd *Command, arg, next string) bool {
	name, _, carriesValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	if next == "" || carriesValue || name == "" || name == HelpFlag {
		return false
	}
	if flag, known := cmd.Flag(name); known {
		return flag.Type != "bool"
	}
	return !strings.HasPrefix(next, "-")
}

// shortFlagTakesNext reports whether the argument after a "-x" token, or a
// "-xyz" cluster, is a value of that cluster. pflag clusters booleans freely,
// and the first flag that takes a value swallows the rest of the token
// ("-oresults.json", "-o=results.json") or, when the token ends there, the next
// argument ("-o results.json").
func shortFlagTakesNext(cmd *Command, arg, next string) bool {
	if next == "" {
		return false
	}
	cluster := []rune(strings.TrimPrefix(arg, "-"))
	for i := 0; i < len(cluster); i++ {
		r := cluster[i]
		if !isShorthandRune(r) {
			return false
		}
		if r == 'h' {
			continue
		}
		flag, ok := cmd.FlagByShorthand(string(r))
		switch {
		case !ok:
			// Unknown, so whether the rest of the token is more shorthands or a
			// value is unknowable. Reported by checkShortFlags; guessing here
			// would only move the damage.
			return false
		case flag.Type == "bool":
			continue
		}
		return strings.TrimPrefix(string(cluster[i+1:]), "=") == ""
	}
	return false
}

// checkLongFlag validates a "--<name>" or "--<name>=<value>" token against cmd.
func checkLongFlag(s Surface, cmd *Command, file string, line int, arg string, allow Allowlist) []Issue {
	name, _, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	written := "--" + name
	if name == "" || name == HelpFlag || allow.Allows(written) {
		return nil
	}

	flag, ok := cmd.Flag(name)
	switch {
	case ok && flag.Rejected:
		// No edit-distance suggestion here: the command's own rejection
		// message already names the flag to use instead.
		return []Issue{{
			File: file, Line: line, Token: written, Command: cmd.Path,
			Reason: "is rejected by this command: " + flag.RejectedReason + ", so it is not usable on",
		}}
	case ok:
		return nil
	}

	reason := "is not a flag of"
	if contains(s.FlagNames(), name) {
		reason = "exists on other commands but not on"
	}
	return []Issue{{
		File: file, Line: line, Token: written, Command: cmd.Path,
		Reason:     reason,
		Suggestion: nearest(name, usableFlagNames(cmd)),
	}}
}

// checkShortFlags validates a "-x" token, or a "-xyz" cluster, against cmd. It
// reads the cluster the way pflag does (see shortFlagTakesNext): scanning a
// flag's value as more shorthands is how "-oresults.json" turns into six
// invented flags.
func checkShortFlags(cmd *Command, file string, line int, arg string, allow Allowlist) []Issue {
	var issues []Issue

	cluster := []rune(strings.TrimPrefix(arg, "-"))
	for i := 0; i < len(cluster); i++ {
		r := cluster[i]
		if !isShorthandRune(r) {
			// Not a shorthand, so this token is a value rather than a cluster.
			return issues
		}

		written := "-" + string(r)
		// -h is cobra's help shorthand, present on every command.
		if r == 'h' || allow.Allows(written) {
			continue
		}

		flag, ok := cmd.FlagByShorthand(string(r))
		if !ok {
			issues = append(issues, Issue{
				File: file, Line: line, Token: written, Command: cmd.Path,
				Reason: "is not a shorthand flag of",
			})
			// Stop here. Without knowing whether this shorthand takes a value
			// there is no way to tell whether the rest of the token is more
			// shorthands or that value, and guessing invents findings.
			return issues
		}
		if flag.Rejected {
			issues = append(issues, Issue{
				File: file, Line: line, Token: written, Command: cmd.Path,
				Reason: "is rejected by this command: " + flag.RejectedReason + ", so it is not usable on",
			})
		}
		if flag.Type != "bool" {
			// A value-taking shorthand ends the cluster.
			return issues
		}
	}
	return issues
}

// isShorthandRune reports whether r can be a pflag shorthand. Anything else
// (a digit sign, a slash, a dot) means the token is a value, not a flag
// cluster, and the rest of it must not be validated.
func isShorthandRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// resolveChild resolves one path segment to a direct subcommand of path, by
// name or by alias.
func resolveChild(s Surface, path, segment string) *Command {
	if c, ok := s.Command(path + " " + segment); ok {
		return c
	}
	for _, c := range s.Children(path) {
		if contains(c.Aliases, segment) {
			return c
		}
	}
	return nil
}

// vocabulary is every flag name documentation may name without saying which
// command it means: the union of the tree's flags plus cobra's help flag.
func vocabulary(s Surface) []string {
	return append(s.FlagNames(), HelpFlag)
}

// usableFlagNames lists the flags actually usable on cmd.
func usableFlagNames(cmd *Command) []string {
	out := make([]string, 0, len(cmd.Flags))
	for i := range cmd.Flags {
		if !cmd.Flags[i].Rejected {
			out = append(out, cmd.Flags[i].Name)
		}
	}
	return out
}

// LintGoComments checks every long-flag token in the comments of one Go file.
// This is the check that keeps a renamed flag from surviving in a comment that
// no compiler and no test would ever read.
func LintGoComments(s Surface, file string, src []byte, allow Allowlist) ([]Issue, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}

	known := vocabulary(s)
	var issues []Issue
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			line := fset.Position(comment.Slash).Line
			for _, tok := range longFlagTokens(comment.Text) {
				name := strings.TrimRight(strings.TrimPrefix(tok, "--"), ".,;:)")
				if name == "" || allow.Allows("--"+name) || contains(known, name) {
					continue
				}
				issues = append(issues, Issue{
					File:       file,
					Line:       line,
					Token:      "--" + name,
					Reason:     "is named in a comment but is not a flag of any command in the CLI",
					Suggestion: nearest(name, known),
				})
			}
		}
	}
	return issues, nil
}

// --- shell tokenising -------------------------------------------------------

// shellSegments splits one logical shell line into pipeline segments of argv
// tokens. It is quote-aware (so a flag value containing '&&', '|' or '#' stays
// one token), honors backslash escapes outside quotes, drops a leading "$"
// prompt, and stops at an unquoted '#' comment.
func shellSegments(line string) [][]string {
	var (
		segments [][]string
		argv     []string
		cur      strings.Builder
		quote    rune
	)

	endToken := func() {
		if cur.Len() > 0 {
			argv = append(argv, cur.String())
			cur.Reset()
		}
	}
	endSegment := func() {
		endToken()
		if len(argv) > 0 {
			segments = append(segments, argv)
			argv = nil
		}
	}

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && quote == '"' && i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
				continue
			}
			cur.WriteRune(c)
		case c == '\'' || c == '"':
			quote = c
		case c == '\\' && i+1 < len(runes):
			i++
			cur.WriteRune(runes[i])
		case c == ' ' || c == '\t':
			endToken()
		case c == '#' && cur.Len() == 0:
			endSegment()
			return segments
		case c == '|' || c == ';' || c == '&' || c == '>' || c == '<' || c == '(' || c == ')':
			endSegment()
		default:
			cur.WriteRune(c)
		}
	}
	endSegment()

	for i := range segments {
		if len(segments[i]) > 1 && segments[i][0] == "$" {
			segments[i] = segments[i][1:]
		}
	}
	return segments
}

// longFlagTokens returns the long-flag tokens in text, in order.
func longFlagTokens(text string) []string {
	matches := longFlagPattern.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[2])
	}
	return out
}

// baseName is the last path element of an argv[0], so "./brutus" and
// "/usr/local/bin/brutus" both name the binary.
func baseName(arg string) string {
	if i := strings.LastIndexAny(arg, `/\`); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// --- suggestions ------------------------------------------------------------

// contains reports whether want is in list.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// nearest returns the closest candidate to name as a "--<flag>" string, or "" if
// nothing is close enough to be a useful suggestion.
func nearest(name string, candidates []string) string {
	best, bestDistance := "", 0
	for _, c := range candidates {
		d := editDistance(name, c)
		if best == "" || d < bestDistance {
			best, bestDistance = c, d
		}
	}
	limit := len(name) / 2
	if limit < 2 {
		limit = 2
	}
	if best == "" || bestDistance > limit {
		return ""
	}
	return "--" + best
}

// nearestCommand returns the closest subcommand name of path to token.
func nearestCommand(s Surface, path, segment string) string {
	var names []string
	for _, c := range s.Children(path) {
		names = append(names, name(c.Path))
		names = append(names, c.Aliases...)
	}
	best, bestDistance := "", 0
	for _, n := range names {
		d := editDistance(segment, n)
		if best == "" || d < bestDistance {
			best, bestDistance = n, d
		}
	}
	if best == "" || bestDistance > 3 {
		return ""
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
