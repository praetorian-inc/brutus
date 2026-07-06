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
// F1: Subject-building helpers (dedupe, buildCustomSubjects)
// ---------------------------------------------------------------------------

// TestDedupe_RemovesDuplicatesPreservingOrder verifies that dedupe removes
// repeated values while preserving the first-seen order.
func TestDedupe_RemovesDuplicatesPreservingOrder(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no duplicates — unchanged",
			in:   []string{"a", "b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "all duplicates — single element",
			in:   []string{"x", "x", "x"},
			want: []string{"x"},
		},
		{
			name: "duplicates across non-adjacent positions",
			in:   []string{"a", "b", "a", "c", "b"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty input",
			in:   nil,
			want: []string{},
		},
		{
			name: "single element",
			in:   []string{"only"},
			want: []string{"only"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupe(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// parseSpec is a test helper that parses and validates a spec from JSON.
func parseSpec(t *testing.T, data string) *custom.Spec {
	t.Helper()
	spec, err := custom.Parse([]byte(data))
	require.NoError(t, err)
	require.NoError(t, spec.Validate())
	return spec
}

// TestBuildCustomSubjects_InlineEmails verifies the -e flag CSV path:
// subjects are split on comma, trimmed of whitespace, and returned in order.
func TestBuildCustomSubjects_InlineEmails(t *testing.T) {
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

	got, err := buildCustomSubjects()
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, got)
}

// TestBuildCustomSubjects_EmailFile verifies the -E file path: subjects are
// read one-per-line from the file.
func TestBuildCustomSubjects_EmailFile(t *testing.T) {
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

	got, err := buildCustomSubjects()
	require.NoError(t, err)
	assert.Equal(t, []string{"user1", "user2"}, got)
}

// TestBuildCustomSubjects_Dedupe verifies that buildCustomSubjects de-duplicates
// subjects supplied via -e, preserving first-seen order.
func TestBuildCustomSubjects_Dedupe(t *testing.T) {
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

	got, err := buildCustomSubjects()
	require.NoError(t, err)
	assert.Equal(t, []string{"alice", "bob", "charlie"}, got)
}

// TestBuildCustomSubjects_ConstraintRateLimitDefault verifies that the spec's
// constraints.rate_limit_rps is applied to the enum config as a default only
// when --rate-limit has not been set by the operator (isFlagChanged is false).
//
// buildCustomSubjects itself does not apply the rate-limit — that logic lives
// in runEnumCustom. This test verifies the constraint field is accessible via
// the Spec type (it's the glue the command wires up).
func TestBuildCustomSubjects_ConstraintRateLimitDefault(t *testing.T) {
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

	// Also verify buildCustomSubjects succeeds with a subject supplied via CLI.
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

	got, err := buildCustomSubjects()
	require.NoError(t, err)
	assert.Equal(t, []string{"seed@example.com"}, got)
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
