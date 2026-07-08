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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	githubenum "github.com/praetorian-inc/brutus/pkg/enum/github"
)

// ---------------------------------------------------------------------------
// Flag registration
// ---------------------------------------------------------------------------

// TestEnumGithubMapCmd_Flags verifies that enumGithubMapCmd carries the
// required flags and shorthands, and that no shorthand collides with the
// global persistent --threads/-t flag.
func TestEnumGithubMapCmd_Flags(t *testing.T) {
	// --emails / -e
	f := enumGithubMapCmd.Flags().Lookup("emails")
	require.NotNil(t, f, "--emails flag must exist on enumGithubMapCmd")
	sh := enumGithubMapCmd.Flags().ShorthandLookup("e")
	require.NotNil(t, sh, "-e shorthand must exist on enumGithubMapCmd")
	assert.Equal(t, "emails", sh.Name, "-e must map to --emails")

	// --email-file / -E
	f = enumGithubMapCmd.Flags().Lookup("email-file")
	require.NotNil(t, f, "--email-file flag must exist on enumGithubMapCmd")
	sh = enumGithubMapCmd.Flags().ShorthandLookup("E")
	require.NotNil(t, sh, "-E shorthand must exist on enumGithubMapCmd")
	assert.Equal(t, "email-file", sh.Name, "-E must map to --email-file")

	// --token (no shorthand; -t collides with global persistent --threads/-t)
	f = enumGithubMapCmd.Flags().Lookup("token")
	require.NotNil(t, f, "--token flag must exist on enumGithubMapCmd")

	// No -t shorthand: it collides with the global persistent --threads/-t.
	noT := enumGithubMapCmd.Flags().ShorthandLookup("t")
	require.Nil(t, noT,
		"enumGithubMapCmd must not define a local -t shorthand (collides with global --threads/-t)")
}

// ---------------------------------------------------------------------------
// Command wiring
// ---------------------------------------------------------------------------

// TestEnumGithubMapCmd_WiredUnderGithub verifies that enumGithubMapCmd is
// registered as a child of enumGithubCmd with Use == "map".
func TestEnumGithubMapCmd_WiredUnderGithub(t *testing.T) {
	var found bool
	for _, cmd := range enumGithubCmd.Commands() {
		if cmd.Use == "map" {
			found = true
			break
		}
	}
	assert.True(t, found, `enumGithubCmd must have a "map" subcommand`)
}

// ---------------------------------------------------------------------------
// collectGithubEmails
// ---------------------------------------------------------------------------

// TestCollectGithubEmails exercises the shared email-collection helper with
// table-driven cases covering CSV dedup+trim, generated appending, and the
// no-source sentinel error path.
func TestCollectGithubEmails(t *testing.T) {
	tests := []struct {
		name        string
		emailsCSV   string
		emailFile   string
		generated   []string
		noSourceErr error
		wantEmails  []string
		wantErrIs   error // non-nil → expect an error satisfying errors.Is
	}{
		{
			name:        "CSV dedup + trim + order",
			emailsCSV:   " a@x.com , b@x.com ,a@x.com ",
			emailFile:   "",
			generated:   nil,
			noSourceErr: errors.New("provide --emails/-e or --email-file/-E"),
			wantEmails:  []string{"a@x.com", "b@x.com"},
		},
		{
			name:        "generated appended and deduped",
			emailsCSV:   "a@x.com",
			emailFile:   "",
			generated:   []string{"b@x.com", "a@x.com", "c@x.com"},
			noSourceErr: errors.New("provide --emails/-e or --email-file/-E"),
			wantEmails:  []string{"a@x.com", "b@x.com", "c@x.com"},
		},
		{
			name:        "no source returns sentinel error verbatim",
			emailsCSV:   "",
			emailFile:   "",
			generated:   nil,
			noSourceErr: errors.New("provide --emails/-e or --email-file/-E"),
			wantErrIs:   errors.New("provide --emails/-e or --email-file/-E"),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Build the sentinel error for this case (so we can use errors.Is).
			sentinel := tc.noSourceErr

			got, err := collectGithubEmails(tc.emailsCSV, tc.emailFile, tc.generated, sentinel)

			if tc.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, sentinel,
					"collectGithubEmails must return the exact sentinel error when no source is supplied")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantEmails, got,
				"email slice must be trimmed, deduped, and in first-seen order")
		})
	}
}

// ---------------------------------------------------------------------------
// githubMapResults
// ---------------------------------------------------------------------------

// TestGithubMapResults verifies that githubMapResults builds per-email results
// from the reveal mapping, preserving input order and correctly marking
// presence/absence in the mapping.
func TestGithubMapResults(t *testing.T) {
	emails := []string{"a@x.com", "b@x.com", "c@x.com"}
	mapping := map[string]string{
		"a@x.com": "alice",
		"c@x.com": "carol",
	}

	results := githubMapResults(emails, mapping)

	require.Len(t, results, 3)

	// index 0: a@x.com → mapped to "alice"
	assert.Equal(t, githubenum.Result{
		Email:    "a@x.com",
		Exists:   true,
		Username: "alice",
	}, results[0])

	// index 1: b@x.com → not in mapping
	assert.Equal(t, githubenum.Result{
		Email:    "b@x.com",
		Exists:   false,
		Username: "",
	}, results[1])

	// index 2: c@x.com → mapped to "carol"
	assert.Equal(t, githubenum.Result{
		Email:    "c@x.com",
		Exists:   true,
		Username: "carol",
	}, results[2])
}
