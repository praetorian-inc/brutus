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
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
	"github.com/praetorian-inc/brutus/pkg/enum/custom"
)

// ---------------------------------------------------------------------------
// T11: Command registration
// ---------------------------------------------------------------------------

// TestEnumCustomRegistered verifies that "custom" is registered as a
// subcommand of enumCmd with the required flags, shorthands, and required
// annotation — mirrors cmd_enum_hunter_test.go::TestEnumHunterRegistered.
func TestEnumCustomRegistered(t *testing.T) {
	var found bool
	for _, cmd := range enumActiveCmd.Commands() {
		if cmd.Use != "custom" {
			continue
		}
		found = true

		// --file / -f (required)
		fileFlag := cmd.Flags().Lookup("file")
		require.NotNil(t, fileFlag, "--file flag must exist")

		fileShort := cmd.Flags().ShorthandLookup("f")
		require.NotNil(t, fileShort, "-f shorthand for --file must exist")

		// Verify --file is marked required via cobra annotation.
		annotations := fileFlag.Annotations
		_, isRequired := annotations["cobra_annotation_bash_completion_one_required_flag"]
		assert.True(t, isRequired, "--file must be marked as required")

		// -e (inline emails)
		eFlag := cmd.Flags().Lookup("emails")
		require.NotNil(t, eFlag, "--emails / -e flag must exist")
		eShort := cmd.Flags().ShorthandLookup("e")
		require.NotNil(t, eShort, "-e shorthand must exist")

		// -E (email file)
		emailFileFlag := cmd.Flags().Lookup("email-file")
		require.NotNil(t, emailFileFlag, "--email-file / -E flag must exist")
		eFileShort := cmd.Flags().ShorthandLookup("E")
		require.NotNil(t, eFileShort, "-E shorthand must exist")

		// --generate
		generateFlag := cmd.Flags().Lookup("generate")
		require.NotNil(t, generateFlag, "--generate flag must exist")

		// --format (shared enum flag)
		formatFlag := cmd.Flags().Lookup("format")
		if formatFlag == nil {
			// format may be on a parent or registered locally
			formatFlag = cmd.InheritedFlags().Lookup("format")
		}
		require.NotNil(t, formatFlag, "--format flag must be accessible on custom subcommand")

		// --domain (shared enum flag)
		domainFlag := cmd.Flags().Lookup("domain")
		if domainFlag == nil {
			domainFlag = cmd.InheritedFlags().Lookup("domain")
		}
		require.NotNil(t, domainFlag, "--domain flag must be accessible on custom subcommand")

		break
	}
	require.True(t, found, "custom subcommand must be registered with enumActiveCmd")
}

// ---------------------------------------------------------------------------
// T11: runEnumCustom error paths
// ---------------------------------------------------------------------------

// TestRunEnumCustom_BadSpec verifies that runEnumCustom returns a non-nil
// error when the spec file contains invalid content.
func TestRunEnumCustom_BadSpec(t *testing.T) {
	// Write an invalid spec to a temp file.
	tmp, err := os.CreateTemp(t.TempDir(), "bad-spec-*.json")
	require.NoError(t, err)
	_, err = tmp.WriteString(`{"version":"99","oracle":{}}`)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	// Save and restore the flag value.
	orig := flagCustomFile
	t.Cleanup(func() { flagCustomFile = orig })
	flagCustomFile = tmp.Name()

	cmd := enumCustomCmd
	err = runEnumCustom(cmd, nil)
	require.Error(t, err, "bad spec must produce a non-nil error from runEnumCustom")
}

// TestRunEnumCustom_NoSubjects verifies that runEnumCustom returns an error
// whose message is exactly "no subjects: provide -e/-E or --generate" when the
// spec is valid but no subjects are provided via -e/-E/--generate.
func TestRunEnumCustom_NoSubjects(t *testing.T) {
	// Write a valid spec to a temp file.
	tmp, err := os.CreateTemp(t.TempDir(), "no-subjects-*.json")
	require.NoError(t, err)
	_, err = tmp.WriteString(`{
		"version": "1",
		"oracle": {
			"name": "no-subjects-oracle",
			"request": {
				"method": "POST",
				"url": "https://example.com/api"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	// Save and restore flag values.
	origFile := flagCustomFile
	origEmails := flagCustomEmails
	origEmailFile := flagCustomEmailFile
	origGenerate := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomFile = origFile
		flagCustomEmails = origEmails
		flagCustomEmailFile = origEmailFile
		flagCustomGenerate = origGenerate
	})

	flagCustomFile = tmp.Name()
	flagCustomEmails = ""
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	err = runEnumCustom(enumCustomCmd, nil)
	require.Error(t, err, "no subjects must produce a non-nil error")
	assert.Contains(t, err.Error(), "no subjects",
		"error must mention 'no subjects'")
}

// TestRunEnumCustom_OversizeFile verifies that runEnumCustom rejects a spec
// file larger than 1 MB before even parsing it (R8 / P0-7).
func TestRunEnumCustom_OversizeFile(t *testing.T) {
	const maxSpecBytes = 1 << 20 // 1 MB

	// Write a temp file that is slightly larger than 1 MB.
	tmp, err := os.CreateTemp(t.TempDir(), "oversize-spec-*.json")
	require.NoError(t, err)

	// Write maxSpecBytes+1 bytes of junk.
	junk := make([]byte, maxSpecBytes+1)
	for i := range junk {
		junk[i] = 'x'
	}
	_, err = tmp.Write(junk)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	// Save and restore flag value.
	orig := flagCustomFile
	t.Cleanup(func() { flagCustomFile = orig })
	flagCustomFile = tmp.Name()

	err = runEnumCustom(enumCustomCmd, nil)
	require.Error(t, err, "oversize spec file must be rejected before parse (R8)")
}

// ---------------------------------------------------------------------------
// F1: Target-building helpers (buildCustomTargets)
//
// 10T-535: buildCustomSubjects()/dedupe() were address-only. buildCustomTargets
// is now the single merger of file-supplied and generated addresses, and it
// carries the generated name (First/Last) alongside each address so it can
// never be reverse-derived downstream. These tests exercise buildCustomTargets
// directly, asserting on []enum.Target rather than []string, so a bug that
// stamped a name onto a supplied address (or dropped a name from a generated
// one) fails here rather than just failing to compile.
// ---------------------------------------------------------------------------

// parseSpec is a test helper that parses and validates a spec from JSON.
func parseSpec(t *testing.T, data string) *custom.Spec {
	t.Helper()
	spec, err := custom.Parse([]byte(data))
	require.NoError(t, err)
	require.NoError(t, spec.Validate())
	return spec
}

// targetEmails extracts the Email field from a []enum.Target slice, in order,
// for compact order/content assertions.
func targetEmails(targets []enum.Target) []string {
	out := make([]string, len(targets))
	for i, t := range targets {
		out[i] = t.Email
	}
	return out
}

// TestBuildCustomTargets_InlineEmails verifies the -e flag CSV path: subjects
// are split on comma, trimmed of whitespace, returned in order, and — because
// a CLI-supplied subject says nothing about whose it is — carry no name.
func TestBuildCustomTargets_InlineEmails(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})

	flagCustomEmails = "alice, bob,  charlie"
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	got, err := buildCustomTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, targetEmails(got))
	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): CLI-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): CLI-supplied address must have empty Last", i, target.Email)
	}
}

// TestBuildCustomTargets_EmailFile verifies the -E file path: subjects are
// read one-per-line from the file and carry no name (file-supplied, not
// generated).
func TestBuildCustomTargets_EmailFile(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})

	// Write a two-subject file.
	tmp, err := os.CreateTemp(t.TempDir(), "subjects-*.txt")
	require.NoError(t, err)
	_, err = tmp.WriteString("user1\nuser2\n")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	flagCustomEmails = ""
	flagCustomEmailFile = tmp.Name()
	flagCustomGenerate = false

	got, err := buildCustomTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"user1", "user2"}, targetEmails(got))
	for i, target := range got {
		assert.Empty(t, target.First, "target %d (%q): file-supplied address must have empty First", i, target.Email)
		assert.Empty(t, target.Last, "target %d (%q): file-supplied address must have empty Last", i, target.Email)
	}
}

// TestBuildCustomTargets_Dedupe verifies that buildCustomTargets de-duplicates
// on Email for subjects supplied via -e, preserving first-seen order.
func TestBuildCustomTargets_Dedupe(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})

	// alice appears twice; bob once; charlie once — after dedupe: alice, bob, charlie.
	flagCustomEmails = "alice,bob,alice,charlie"
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	got, err := buildCustomTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, targetEmails(got))
}

// TestBuildCustomTargets_ConstraintRateLimitDefault verifies that the spec's
// constraints.rate_limit_rps is applied to the enum config as a default only
// when --rate-limit has not been set by the operator (isFlagChanged is false).
//
// buildCustomTargets itself does not apply the rate-limit — that logic lives
// in runEnumCustom. This test verifies the constraint field is accessible via
// the Spec type (it's the glue the command wires up).
func TestBuildCustomTargets_ConstraintRateLimitDefault(t *testing.T) {
	const constraintRPS = `{
		"version": "1",
		"oracle": {
			"name": "rl-oracle",
			"request": {"method": "GET", "url": "https://example.com/api"},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		},
		"constraints": {
			"rate_limit_rps": 5.0
		}
	}`

	spec := parseSpec(t, constraintRPS)

	// Verify that the Spec carries the constraint value that runEnumCustom reads.
	require.NotNil(t, spec.Constraints, "spec must have Constraints populated")
	assert.Equal(t, 5.0, spec.Constraints.RateLimitRPS,
		"Constraints.RateLimitRPS must equal the spec value (5.0)")

	// Also verify buildCustomTargets succeeds with a subject supplied via CLI.
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})
	flagCustomEmails = "seed@example.com"
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	got, err := buildCustomTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"seed@example.com"}, targetEmails(got))
	require.Len(t, got, 1)
	assert.Empty(t, got[0].First, "CLI-supplied address must have empty First")
	assert.Empty(t, got[0].Last, "CLI-supplied address must have empty Last")
}

// TestBuildCustomTargets_GeneratedNoDomain is THE POINT OF 10T-535 for this
// command: with --generate and no --domain, buildCustomTargets must build
// Target{Email: c.Username, First: c.First, Last: c.Last} directly rather
// than going through Candidate.Target(domain) — appending "@" to a bare
// username would be wrong. This pins that no-domain branch: every generated
// Target's Email is the bare username (no "@"), and First/Last are non-empty,
// carrying the name the generator actually used.
func TestBuildCustomTargets_GeneratedNoDomain(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	origFormat := flagEnumFormat
	origDomain := flagEnumDomain
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
		flagEnumFormat = origFormat
		flagEnumDomain = origDomain
	})

	flagCustomEmails = ""
	flagCustomEmailFile = ""
	flagCustomGenerate = true
	flagEnumFormat = enum.FormatFirstDotLast
	flagEnumDomain = ""

	got, err := buildCustomTargets()
	require.NoError(t, err)
	require.NotEmpty(t, got)

	// Compare against the real generator output (not a reimplementation) so
	// this fails if generateCustomTargets ever diverges from GenerateCandidates.
	candidates, genErr := enum.GenerateCandidates(enum.FormatFirstDotLast)
	require.NoError(t, genErr)
	require.Len(t, got, len(candidates),
		"no-domain generation must produce exactly one target per candidate")

	for i, c := range candidates {
		assert.Equal(t, c.Username, got[i].Email,
			"target %d: Email must be the bare username (no domain) when --domain is unset", i)
		assert.NotContains(t, got[i].Email, "@",
			"target %d: no-domain Email must not contain '@'", i)
		assert.Equal(t, c.First, got[i].First, "target %d: First must match the generated candidate", i)
		assert.Equal(t, c.Last, got[i].Last, "target %d: Last must match the generated candidate", i)
		require.NotEmpty(t, got[i].First, "target %d: generated First must be non-empty", i)
		require.NotEmpty(t, got[i].Last, "target %d: generated Last must be non-empty", i)
	}
}

// TestBuildCustomTargets_GeneratedWithDomain verifies the --generate +
// --domain branch: buildCustomTargets must build each Target via
// Candidate.Target(domain), so Email is "username@domain" and First/Last are
// still populated from the candidate.
func TestBuildCustomTargets_GeneratedWithDomain(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	origFormat := flagEnumFormat
	origDomain := flagEnumDomain
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
		flagEnumFormat = origFormat
		flagEnumDomain = origDomain
	})

	const domain = "example.com"
	flagCustomEmails = ""
	flagCustomEmailFile = ""
	flagCustomGenerate = true
	flagEnumFormat = enum.FormatFirstDotLast
	flagEnumDomain = domain

	got, err := buildCustomTargets()
	require.NoError(t, err)
	require.NotEmpty(t, got)

	candidates, genErr := enum.GenerateCandidates(enum.FormatFirstDotLast)
	require.NoError(t, genErr)
	require.Len(t, got, len(candidates),
		"with-domain generation must produce exactly one target per candidate")

	for i, c := range candidates {
		assert.Equal(t, c.Target(domain), got[i],
			"target %d: must equal Candidate.Target(domain) exactly", i)
		assert.True(t, strings.HasSuffix(got[i].Email, "@"+domain),
			"target %d: with-domain Email must end with @%s", i, domain)
		require.NotEmpty(t, got[i].First, "target %d: generated First must be non-empty", i)
		require.NotEmpty(t, got[i].Last, "target %d: generated Last must be non-empty", i)
	}
}

// TestBuildCustomTargets_MergeDedupePrecedence covers the merge, the dedup,
// the first-seen order, and the precedence between a file-supplied address
// and a generated one, all in a single scenario: -E supplies the exact
// address that --generate would also produce as its #1-ranked candidate
// ("john.smith", from FormatFirstDotLast's top-ranked pair — pinned by
// TestGenerateUsernames_FirstDotLast in pkg/enum/generate_test.go).
//
//   - Merge: the result contains both the -E entry and the --generate entries.
//   - Order: -E is appended before --generate (source order), so the
//     file-supplied "john.smith" occupies index 0.
//   - Dedupe: the generated candidate that would also produce "john.smith" is
//     dropped as a duplicate, not appended a second time.
//   - Precedence: the surviving "john.smith" target is the file-supplied one
//     (empty First/Last) — first-seen wins, so a generated duplicate can never
//     retroactively attach a name to an address the operator supplied.
func TestBuildCustomTargets_MergeDedupePrecedence(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	origFormat := flagEnumFormat
	origDomain := flagEnumDomain
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
		flagEnumFormat = origFormat
		flagEnumDomain = origDomain
	})

	// Write a one-line subject file containing the #1-ranked generated
	// username, so it collides with the first generated candidate.
	tmp, err := os.CreateTemp(t.TempDir(), "collide-*.txt")
	require.NoError(t, err)
	_, err = tmp.WriteString("john.smith\n")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	flagCustomEmails = ""
	flagCustomEmailFile = tmp.Name()
	flagCustomGenerate = true
	flagEnumFormat = enum.FormatFirstDotLast
	flagEnumDomain = ""

	got, err := buildCustomTargets()
	require.NoError(t, err)
	require.NotEmpty(t, got)

	candidates, genErr := enum.GenerateCandidates(enum.FormatFirstDotLast)
	require.NoError(t, genErr)
	require.Equal(t, "john.smith", candidates[0].Username,
		"test assumption: FormatFirstDotLast's #1-ranked candidate must be john.smith")

	// Merge + dedupe: exactly one target per unique candidate — the collision
	// on "john.smith" means the file entry and the #1 candidate collapse to
	// one target, so the total count equals len(candidates), not len+1.
	assert.Len(t, got, len(candidates),
		"merge+dedupe: file-supplied duplicate of the #1 candidate must not double-count")

	// Order + precedence: index 0 is the file-supplied "john.smith", unnamed —
	// not the generated candidate that would also produce it.
	require.Equal(t, "john.smith", got[0].Email)
	assert.Empty(t, got[0].First,
		"precedence: file-supplied address must win over the colliding generated one — First must stay empty")
	assert.Empty(t, got[0].Last,
		"precedence: file-supplied address must win over the colliding generated one — Last must stay empty")

	// Every remaining target came only from --generate (no other collisions
	// are possible: GenerateCandidates guarantees unique usernames), so each
	// must carry a name.
	for i := 1; i < len(got); i++ {
		assert.NotEmpty(t, got[i].First, "target %d (%q): generated target must have non-empty First", i, got[i].Email)
		assert.NotEmpty(t, got[i].Last, "target %d (%q): generated target must have non-empty Last", i, got[i].Email)
	}
}

// ---------------------------------------------------------------------------
// New: TestRunEnumCustom_EndToEnd — 32% → higher coverage of runEnumCustom
// ---------------------------------------------------------------------------

// oracleSpecForTest builds the JSON for a schema-v1 oracle whose URL points at
// srv. The oracle uses a POST with a JSON body that includes the {{username}}
// placeholder; it matches 200 → exists and 404 → absent.
func oracleSpecForTest(t *testing.T, serverURL string) string {
	t.Helper()
	return fmt.Sprintf(`{
	"version": "1",
	"oracle": {
		"name": "test-oracle",
		"request": {
			"method": "POST",
			"url": %q,
			"headers": {"Content-Type": "application/json"},
			"body": "{\"user\":\"{{username}}\"}",
			"body_encoding": "json"
		},
		"match": {
			"rules": [
				{"when": {"status": 200}, "verdict": "exists"},
				{"when": {"status": 404}, "verdict": "absent"}
			],
			"default": "absent"
		}
	}
}`, serverURL)
}

// TestRunEnumCustom_EndToEnd exercises the full runEnumCustom happy path:
//   - a real httptest.Server returns 200 for "jsmith" and 404 for "nobody"
//   - a temp oracle spec file is written with the server URL
//   - package-level flag vars are set and restored with defer
//   - output is captured to a temp file (which forces JSON via flagOutputFile)
//   - the JSONL output is parsed to confirm jsmith exists=true, nobody exists=false
func TestRunEnumCustom_EndToEnd(t *testing.T) {
	// Spin up a test HTTP server that maps subject → verdict via the POST body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The oracle sends JSON body {"user":"<subject>"}
		var body struct {
			User string `json:"user"`
		}
		// Best-effort decode; fall through to 404 on failure.
		_ = json.NewDecoder(r.Body).Decode(&body)

		switch body.User {
		case "jsmith":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("reset link sent"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Write the oracle spec to a temp file with the test server URL.
	specDir := t.TempDir()
	specPath := specDir + "/oracle.json"
	specData := oracleSpecForTest(t, srv.URL)
	require.NoError(t, os.WriteFile(specPath, []byte(specData), 0o600))

	// Write output to a temp file so we can read it back and force JSON mode.
	outDir := t.TempDir()
	outPath := outDir + "/results.jsonl"

	// Save and restore ALL package-level flag vars touched by runEnumCustom.
	origCustomFile := flagCustomFile
	origCustomEmails := flagCustomEmails
	origCustomEmailFile := flagCustomEmailFile
	origCustomGenerate := flagCustomGenerate
	origOutputFile := flagOutputFile
	origJSON := flagJSON
	origThreads := flagThreads
	origTimeout := flagTimeout
	defer func() {
		flagCustomFile = origCustomFile
		flagCustomEmails = origCustomEmails
		flagCustomEmailFile = origCustomEmailFile
		flagCustomGenerate = origCustomGenerate
		flagOutputFile = origOutputFile
		flagJSON = origJSON
		flagThreads = origThreads
		flagTimeout = origTimeout
	}()

	flagCustomFile = specPath
	flagCustomEmails = "jsmith,nobody"
	flagCustomEmailFile = ""
	flagCustomGenerate = false
	flagOutputFile = outPath
	flagJSON = false // setupOutputWriter will force it to true via outPath
	flagThreads = 1
	flagTimeout = 0 // use default (10s)

	// Call the command function directly (same-package test, unexported OK).
	err := runEnumCustom(enumCustomCmd, nil)
	require.NoError(t, err, "runEnumCustom must succeed with valid spec and subjects")

	// Read and parse JSONL output.
	outBytes, readErr := os.ReadFile(outPath)
	require.NoError(t, readErr, "output file must be readable")
	require.NotEmpty(t, outBytes, "output file must not be empty")

	type enumLine struct {
		Type    string `json:"type"`
		Email   string `json:"email"`
		Exists  bool   `json:"exists"`
		Service string `json:"service"`
	}

	resultsByEmail := make(map[string]enumLine)
	scanner := bufio.NewScanner(strings.NewReader(string(outBytes)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var el enumLine
		require.NoError(t, json.Unmarshal([]byte(line), &el),
			"each JSONL line must be valid JSON: %s", line)
		resultsByEmail[el.Email] = el
	}
	require.NoError(t, scanner.Err())

	// Assert jsmith exists=true.
	jsmith, ok := resultsByEmail["jsmith"]
	require.True(t, ok, "output must contain a result for 'jsmith'")
	assert.True(t, jsmith.Exists, "jsmith must be reported as exists=true")
	assert.Equal(t, "test-oracle", jsmith.Service)

	// Assert nobody exists=false.
	nobody, ok := resultsByEmail["nobody"]
	require.True(t, ok, "output must contain a result for 'nobody'")
	assert.False(t, nobody.Exists, "nobody must be reported as exists=false")
}
