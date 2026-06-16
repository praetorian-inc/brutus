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
	"os"
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
	for _, cmd := range enumCmd.Commands() {
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
	require.True(t, found, "custom subcommand must be registered with enumCmd")
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
// when the spec is valid but no subjects are provided via -e/-E/--generate
// and the spec has no targets.
func TestRunEnumCustom_NoSubjects(t *testing.T) {
	// Write a valid spec to a temp file (no targets section).
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
// F1: Subject-building helpers (dedupe, prependKnownValid, buildCustomSubjects)
// ---------------------------------------------------------------------------

// TestDedupe_RemovesDuplicatesPreservingOrder verifies that dedupe removes
// repeated values while preserving the first-seen order.
func TestDedupe_RemovesDuplicatesPreservingOrder(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		want  []string
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

// TestPrependKnownValid_SeedsComeFirst verifies that prependKnownValid places
// seeds at the front of the list, followed by the remaining subjects, without
// deduplication (dedupe is a separate step applied by buildCustomSubjects).
func TestPrependKnownValid_SeedsComeFirst(t *testing.T) {
	tests := []struct {
		name  string
		seeds []string
		rest  []string
		want  []string
	}{
		{
			name:  "seeds before rest",
			seeds: []string{"seed1", "seed2"},
			rest:  []string{"other1", "other2"},
			want:  []string{"seed1", "seed2", "other1", "other2"},
		},
		{
			name:  "empty rest",
			seeds: []string{"seed1"},
			rest:  nil,
			want:  []string{"seed1"},
		},
		{
			name:  "empty seeds",
			seeds: nil,
			rest:  []string{"a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "seeds duplicated in rest — returned as-is (dedup is caller's job)",
			seeds: []string{"seed1"},
			rest:  []string{"seed1", "other"},
			want:  []string{"seed1", "seed1", "other"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prependKnownValid(tc.seeds, tc.rest)
			assert.Equal(t, tc.want, got)
		})
	}
}

// minimalSpecJSON returns JSON for a valid spec with no targets section.
// Used by buildCustomSubjects tests to avoid a real file dependency.
const minimalSpecJSON = `{
	"version": "1",
	"oracle": {
		"name": "test-oracle",
		"request": {
			"method": "POST",
			"url": "https://example.com/api"
		},
		"match": {
			"rules": [{"when": {"status": 200}, "verdict": "exists"}],
			"default": "error"
		}
	}
}`

// specWithTargets returns a spec JSON that includes a known_valid targets
// section with the supplied seeds.
func specWithTargets(seeds ...string) string {
	encoded := `"`
	for i, s := range seeds {
		if i > 0 {
			encoded += `", "`
		}
		encoded += s
	}
	encoded += `"`
	return `{
		"version": "1",
		"oracle": {
			"name": "test-oracle",
			"request": {
				"method": "POST",
				"url": "https://example.com/api"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		},
		"targets": {
			"known_valid": [` + encoded + `]
		}
	}`
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

	spec := parseSpec(t, minimalSpecJSON)
	got, err := buildCustomSubjects(spec, false)
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

	spec := parseSpec(t, minimalSpecJSON)
	got, err := buildCustomSubjects(spec, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"user1", "user2"}, got)
}

// TestBuildCustomSubjects_TargetsFallback verifies that when no CLI flags are
// set, the spec's known_valid targets are used as the subject list.
func TestBuildCustomSubjects_TargetsFallback(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})

	flagCustomEmails = ""
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	spec := parseSpec(t, specWithTargets("seed1", "seed2"))
	got, err := buildCustomSubjects(spec, false)
	require.NoError(t, err)
	// When falling back to targets, known_valid is used directly then
	// prependKnownValid+dedupe produces exactly the seeds.
	assert.Equal(t, []string{"seed1", "seed2"}, got)
}

// TestBuildCustomSubjects_KnownValidPrependedAndDeduped verifies that when CLI
// subjects are supplied AND the spec has known_valid, the seeds are prepended
// and duplicates are removed.
func TestBuildCustomSubjects_KnownValidPrependedAndDeduped(t *testing.T) {
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})

	// CLI provides "other" and "seed1" (the latter is also a known_valid seed).
	flagCustomEmails = "other,seed1"
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	spec := parseSpec(t, specWithTargets("seed1", "seed2"))
	got, err := buildCustomSubjects(spec, false)
	require.NoError(t, err)

	// Expected order: seeds first (seed1, seed2), then remaining (other),
	// with seed1 de-duplicated.
	assert.Equal(t, []string{"seed1", "seed2", "other"}, got)
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
		},
		"targets": {
			"known_valid": ["seed@example.com"]
		}
	}`

	spec := parseSpec(t, constraintRPS)

	// Verify that the Spec carries the constraint value that runEnumCustom reads.
	require.NotNil(t, spec.Constraints, "spec must have Constraints populated")
	assert.Equal(t, 5.0, spec.Constraints.RateLimitRPS,
		"Constraints.RateLimitRPS must equal the spec value (5.0)")

	// Also verify buildCustomSubjects succeeds (targets fallback path).
	origEmails := flagCustomEmails
	origFile := flagCustomEmailFile
	origGen := flagCustomGenerate
	t.Cleanup(func() {
		flagCustomEmails = origEmails
		flagCustomEmailFile = origFile
		flagCustomGenerate = origGen
	})
	flagCustomEmails = ""
	flagCustomEmailFile = ""
	flagCustomGenerate = false

	got, err := buildCustomSubjects(spec, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"seed@example.com"}, got)
}
