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
