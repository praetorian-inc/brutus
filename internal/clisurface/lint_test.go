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

// emptyAllowlist is the allowlist used by tests that do not exercise it.
func emptyAllowlist(t *testing.T) Allowlist {
	t.Helper()
	allow, err := ParseAllowlist("")
	require.NoError(t, err)
	return allow
}

// tokensOf flattens issues to their offending tokens.
func tokensOf(issues []Issue) []string {
	out := make([]string, 0, len(issues))
	for i := range issues {
		out = append(out, issues[i].Token)
	}
	return out
}

func TestShellSegmentsSplitsPipelines(t *testing.T) {
	segments := shellSegments("naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt")

	require.Len(t, segments, 3)
	assert.Equal(t, []string{"naabu", "-host", "10.0.0.0/24", "-silent"}, segments[0])
	assert.Equal(t, []string{"nerva", "--json"}, segments[1])
	assert.Equal(t, []string{"brutus", "creds", "-P", "passwords.txt"}, segments[2])
}

func TestShellSegmentsKeepsQuotedValuesWhole(t *testing.T) {
	segments := shellSegments(`brutus logon --target host --exec "net user attacker P@ssw0rd /add && net localgroup administrators attacker /add"`)

	require.Len(t, segments, 1, "the && inside quotes must not split the command")
	assert.Equal(t, []string{
		"brutus", "logon", "--target", "host", "--exec",
		"net user attacker P@ssw0rd /add && net localgroup administrators attacker /add",
	}, segments[0])
}

func TestShellSegmentsHandlesPromptsCommentsAndSeparators(t *testing.T) {
	assert.Equal(t, [][]string{{"brutus", "creds"}}, shellSegments("$ brutus creds"),
		"a copied shell prompt is not argv[0]")
	assert.Equal(t, [][]string{{"brutus", "creds"}}, shellSegments("brutus creds    # test SSH, MySQL, ..."),
		"an unquoted # starts a comment")
	assert.Empty(t, shellSegments("# only a comment"))
	assert.Equal(t, [][]string{{"brutus", "creds"}, {"results.json"}}, shellSegments("brutus creds > results.json"),
		"a redirect target is its own segment, so it is never read as a flag")
	assert.Equal(t, [][]string{{"jq", "-r", `"\(.target) \(.username)"`, "findings.json"}},
		shellSegments(`jq -r '"\(.target) \(.username)"' findings.json`),
		"single quotes are literal")
}

func TestLintMarkdownOnlyChecksTheCLIsOwnInvocations(t *testing.T) {
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"```bash",
		"naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | tool scan",
		"curl -LO https://example.com/tool.tar.gz | tar -xzf -",
		"go install example.com/cmd/tool@latest",
		"sudo mv tool /usr/local/bin/",
		"jq 'select(.finding)' findings.json",
		"```",
	}, "\n")

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	assert.Empty(t, issues, "flags belonging to other tools in the pipeline must never be validated")
}

func TestLintMarkdownReportsFlagsTheCommandDoesNotHave(t *testing.T) {
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"prose line",
		"```bash",
		"tool scan --target host --targt host",
		"```",
	}, "\n")

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--targt", issues[0].Token)
	assert.Equal(t, 3, issues[0].Line, "the issue points at the line inside the fence")
	assert.Equal(t, "tool scan", issues[0].Command)
	assert.Equal(t, "--target", issues[0].Suggestion, "the nearest real flag is offered")
	assert.Contains(t, issues[0].String(), `README.md:3: --targt is not a flag of "tool scan"`,
		"the message names the file, the line, the token and the command")
	assert.Contains(t, issues[0].String(), AllowlistPath, "the message says how to allow a deliberate mention")
}

func TestLintMarkdownReportsFlagsRejectedByTheCommand(t *testing.T) {
	s := Walk(newTestTree())
	doc := "```bash\ntool guarded --timeout 30s\n```"

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1, "--timeout is inherited but the command refuses it")
	assert.Equal(t, "--timeout", issues[0].Token)
	assert.Equal(t, "tool guarded", issues[0].Command)
	assert.Contains(t, issues[0].Reason, "use --scan-timeout", "the command's own error explains the rejection")
	assert.Empty(t, issues[0].Suggestion, "the rejection message is the guidance; an edit-distance guess would add noise")
}

func TestLintMarkdownAcceptsInheritedAndHiddenFlags(t *testing.T) {
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --target host --timeout 5s --json\ntool guarded --scan-timeout 15s --json\n```"

	assert.Empty(t, LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"a flag inherited from the root is usable unless the command rejects it")
}

func TestLintMarkdownJoinsLineContinuations(t *testing.T) {
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"```bash",
		"naabu -host 10.0.0.0/24 -silent | \\",
		"  nerva --json | \\",
		"  tool scan --nope",
		"```",
	}, "\n")

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1, "the continued pipeline is one logical command line")
	assert.Equal(t, "--nope", issues[0].Token)
	assert.Equal(t, 2, issues[0].Line, "a continued line is reported at the line it starts on")
}

func TestLintMarkdownChecksShorthandFlags(t *testing.T) {
	s := Walk(newTestTree())

	assert.Empty(t, LintMarkdown(s, "README.md", "```bash\ntool scan -t host -j\n```", emptyAllowlist(t)))

	issues := LintMarkdown(s, "README.md", "```bash\ntool scan -Z host\n```", emptyAllowlist(t))
	require.Len(t, issues, 1)
	assert.Equal(t, "-Z", issues[0].Token)
	assert.Contains(t, issues[0].Reason, "is not a shorthand flag of")
}

func TestLintMarkdownIgnoresValuesThatLookLikeFlags(t *testing.T) {
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --target - -t -\n```"

	assert.Empty(t, LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"a bare - is stdin, not a flag")
}

func TestLintMarkdownResolvesSubcommandsAndAliases(t *testing.T) {
	s := Walk(newTestTree())

	assert.Empty(t, LintMarkdown(s, "README.md", "```bash\ntool sc --target host\ntool group leaf --only-here x\n```", emptyAllowlist(t)),
		"aliases and nested paths must resolve")

	issues := LintMarkdown(s, "README.md", "```bash\ntool group leef --only-here x\n```", emptyAllowlist(t))
	require.Len(t, issues, 2, "the unknown subcommand and the flag it cannot carry are both reported")
	assert.Equal(t, "leef", issues[0].Token)
	assert.Contains(t, issues[0].Reason, "is not a subcommand of")
	assert.Equal(t, "leaf", issues[0].Suggestion)
}

func TestLintMarkdownTreatsPositionalArgumentsAsValues(t *testing.T) {
	s := Walk(newTestTree())

	assert.Empty(t, LintMarkdown(s, "README.md", "```bash\ntool scan somehost:22\n```", emptyAllowlist(t)),
		"a leaf command's positional argument is not a subcommand")
}

func TestLintMarkdownChecksBacktickedFlagsInProse(t *testing.T) {
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"Route traffic through `--timeout 5s` or use `--mode cautious|default|aggressive`.",
		"Unbackticked --alsogone is ignored because prose says things loosely.",
		"```bash",
		"tool scan --target host",
		"```",
	}, "\n")

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--mode", issues[0].Token)
	assert.Equal(t, 1, issues[0].Line)
	assert.Empty(t, issues[0].Command, "prose is checked against the whole surface, not one command")
	assert.Contains(t, issues[0].Reason, "is not a flag of any command")
}

func TestLintMarkdownIgnoresProseInsideFencesAndFencesInsideProse(t *testing.T) {
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"~~~",
		"tool scan --gone",
		"~~~",
		"`--gone` in prose is reported once more",
	}, "\n")

	issues := LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 2, "a tilde fence is a fence, and prose after it is prose")
	assert.Equal(t, 2, issues[0].Line)
	assert.Equal(t, "tool scan", issues[0].Command)
	assert.Equal(t, 4, issues[1].Line)
	assert.Empty(t, issues[1].Command)
}

func TestLintGoCommentsReportsRenamedFlags(t *testing.T) {
	s := Walk(newTestTree())
	src := []byte(`package demo

// runInteractive handles the --scan-timeout and --sticky-keys-exec modes.
func runInteractive() {}

// ---------------------------------------------------------------------------
// A rule comment and a dash--dash word must not look like flags.
`)

	issues, err := LintGoComments(s, "cmd/demo/demo.go", src, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 1)
	assert.Equal(t, "--sticky-keys-exec", issues[0].Token)
	assert.Equal(t, "cmd/demo/demo.go", issues[0].File)
	assert.Equal(t, 3, issues[0].Line)
	assert.Contains(t, issues[0].Reason, "is named in a comment")
}

func TestLintGoCommentsIgnoresStringLiteralsAndCode(t *testing.T) {
	s := Walk(newTestTree())
	src := []byte(`package demo

func run() string { return "--not-a-real-flag" }
`)

	issues, err := LintGoComments(s, "cmd/demo/demo.go", src, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues, "only comments are checked; string literals are out of scope")
}

func TestLintGoCommentsFailsOnUnparseableSource(t *testing.T) {
	_, err := LintGoComments(Walk(newTestTree()), "cmd/demo/demo.go", []byte("not go at all"), emptyAllowlist(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing cmd/demo/demo.go")
}

func TestAllowlistSuppressesDeliberateMentions(t *testing.T) {
	s := Walk(newTestTree())
	allow, err := ParseAllowlist(strings.Join([]string{
		"# deliberate historical references",
		"--sticky-keys-exec  # renamed to --exec in v1.9; the rename note has to name the old flag",
		"",
		"-Z # nmap's -Z, quoted in a pipeline example",
	}, "\n"))
	require.NoError(t, err)

	assert.Equal(t, []string{"--sticky-keys-exec", "-Z"}, allow.Entries())
	assert.True(t, allow.Allows("--sticky-keys-exec"))
	assert.False(t, allow.Allows("--something-else"))

	doc := "`--sticky-keys-exec` was renamed.\n```bash\ntool scan -Z --sticky-keys-exec\n```"
	assert.Empty(t, LintMarkdown(s, "README.md", doc, allow))
	assert.NotEmpty(t, LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"without the allowlist the same document is reported")
}

func TestParseAllowlistRequiresAReason(t *testing.T) {
	_, err := ParseAllowlist("--orphan\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a '# reason'")

	_, err = ParseAllowlist("--orphan #   \n")
	require.Error(t, err)

	_, err = ParseAllowlist("orphan # missing dashes\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must start with '-'")
}

func TestIssueInAGeneratedFilePointsAtRegeneration(t *testing.T) {
	generated := Issue{File: MarkdownPath, Line: 12, Token: "--gone", Reason: "is not a flag of any command in the CLI"}
	assert.Equal(t,
		"docs/CLI.md:12: --gone is not a flag of any command in the CLI. docs/CLI.md is generated: regenerate it with 'make cli-docs' rather than editing it",
		generated.String(),
		"a stale generated file must not be advertised as something to hand-edit or allowlist")

	for _, file := range []string{"CONTRIBUTING.md", READMEPath} {
		handWritten := Issue{File: file, Line: 12, Token: "--gone", Reason: "is not a flag of any command in the CLI"}
		assert.Contains(t, handWritten.String(), AllowlistPath,
			"%s still offers the allowlist escape hatch: only two regions of README.md are generated", file)
		assert.NotContains(t, handWritten.String(), RegenerateCommand, "%s", file)
	}
}

func TestLintReportNumbersEveryIssue(t *testing.T) {
	report := LintReport([]Issue{
		{File: "README.md", Line: 7, Token: "--gone", Reason: "is not a flag of any command in the CLI"},
		{File: "docs/CLI.md", Line: 9, Token: "--also-gone", Reason: "is not a flag of any command in the CLI"},
	})

	assert.Contains(t, report, "references 2 CLI flag(s)")
	assert.Contains(t, report, "1. README.md:7: --gone")
	assert.Contains(t, report, "2. docs/CLI.md:9: --also-gone")
}

func TestNearestOnlySuggestsPlausibleMatches(t *testing.T) {
	assert.Equal(t, "--target", nearest("targt", []string{"target", "timeout"}))
	assert.Empty(t, nearest("wildly-different", []string{"target", "timeout"}),
		"a distant token gets no suggestion rather than a misleading one")
}

func TestTokensOfIssuesAreStable(t *testing.T) {
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --aaa --bbb\n```"
	assert.Equal(t, []string{"--aaa", "--bbb"}, tokensOf(LintMarkdown(s, "README.md", doc, emptyAllowlist(t))))
}

// TestLintMarkdownResolvesSubcommandsAcrossGlobalFlags pins the fix for the
// linter's worst failure mode: a global flag written before the subcommand used
// to stop subcommand resolution, so every later flag was validated against the
// root and a perfectly valid example was reported as drift.
func TestLintMarkdownResolvesSubcommandsAcrossGlobalFlags(t *testing.T) {
	s := Walk(newTestTree())

	for _, line := range []string{
		"tool --json scan --target host",             // boolean global first
		"tool --timeout 5s scan --target host",       // value-taking global first
		"tool --timeout=5s group leaf --only-here x", // attached value, nested path
		"tool -j scan --target host",                 // boolean shorthand first
		"tool -j --timeout 5s sc --target host",      // several globals, then an alias
	} {
		assert.Empty(t, LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t)),
			"%q is a valid invocation: cobra accepts a global flag before the subcommand", line)
	}
}

// TestLintMarkdownCatchesABadSubcommandAfterAGlobalFlag is the other half of the
// same fix. Resolution used to stop at the first flag, which silently swallowed
// a misspelled subcommand written after one.
func TestLintMarkdownCatchesABadSubcommandAfterAGlobalFlag(t *testing.T) {
	s := Walk(newTestTree())

	issues := LintMarkdown(s, "README.md", "```bash\ntool --json groop leaf\n```", emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "groop", issues[0].Token)
	assert.Equal(t, "tool", issues[0].Command)
	assert.Contains(t, issues[0].Reason, "is not a subcommand of")
	assert.Equal(t, "group", issues[0].Suggestion)
}

// TestLintMarkdownDoesNotReadFlagValuesAsFlags pins the second false-positive
// class: a value that pflag reads as one token used to be scanned as a cluster
// of shorthands, so "-thost" became -t plus five invented flags.
func TestLintMarkdownDoesNotReadFlagValuesAsFlags(t *testing.T) {
	s := Walk(newTestTree())

	for _, line := range []string{
		"tool scan -thost",                  // value attached to the shorthand
		"tool scan -t=host",                 // value attached with =
		"tool scan -t host",                 // value as the next argument
		"tool scan -jt host",                // boolean clustered before a value-taking flag
		"tool scan --target -weird-looking", // a value that starts with a dash
	} {
		assert.Empty(t, LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t)),
			"%q: the flag's value must not be scanned as flags", line)
	}
}

// TestLintMarkdownStopsAtTheDashDashSeparator checks that a token after "--" is
// a positional argument, however much it looks like a flag.
func TestLintMarkdownStopsAtTheDashDashSeparator(t *testing.T) {
	s := Walk(newTestTree())

	assert.Empty(t, LintMarkdown(s, "README.md", "```bash\ntool scan -- --not-a-flag-here\n```", emptyAllowlist(t)),
		"pflag stops parsing flags at a bare --")
}

// TestLintMarkdownStillCatchesFlagsAfterAResolvedSubcommand guards against the
// resolution fix loosening the check: the flags of a correctly resolved deep
// command must still be validated against that command.
func TestLintMarkdownStillCatchesFlagsAfterAResolvedSubcommand(t *testing.T) {
	s := Walk(newTestTree())

	issues := LintMarkdown(s, "README.md", "```bash\ntool --json group leaf --only-here x --gone y\n```", emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--gone", issues[0].Token)
	assert.Equal(t, "tool group leaf", issues[0].Command,
		"the flag is checked against the command the global flag did not hide")
}

// TestSubcommandIssueDoesNotOfferTheFlagAllowlist checks the advice matches the
// token. The allowlist holds flag tokens only, so pointing a misspelled
// subcommand at it would send the reader to write an entry ParseAllowlist
// rejects.
func TestSubcommandIssueDoesNotOfferTheFlagAllowlist(t *testing.T) {
	issue := Issue{
		File: "README.md", Line: 3, Token: "groop", Command: "tool",
		Reason: "is not a subcommand of", Suggestion: "group", Subcommand: true,
	}

	rendered := issue.String()
	assert.Contains(t, rendered, `README.md:3: groop is not a subcommand of "tool"`)
	assert.Contains(t, rendered, "nearest subcommand: group")
	assert.NotContains(t, rendered, "add groop to", "the allowlist parser rejects an entry that is not a flag")

	_, err := ParseAllowlist("groop # what the old message told the reader to write\n")
	require.Error(t, err, "the advice the message used to give was not even valid")
}

// TestLintMarkdownTreatsHelpAsBoolean checks that --help and -h do not swallow
// the token after them: both are boolean, and cobra registers them on every
// command without them appearing in the surface.
func TestLintMarkdownTreatsHelpAsBoolean(t *testing.T) {
	s := Walk(newTestTree())

	issues := LintMarkdown(s, "README.md", "```bash\ntool --help groop\ntool -h groop\n```", emptyAllowlist(t))

	require.Len(t, issues, 2, "the subcommand after --help/-h is still resolved and still checked")
	for i := range issues {
		assert.Equal(t, "groop", issues[i].Token)
		assert.Equal(t, "group", issues[i].Suggestion)
	}
}
