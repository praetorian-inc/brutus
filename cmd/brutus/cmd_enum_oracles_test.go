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
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestEnumOracles_RequiresKnownValid
// ---------------------------------------------------------------------------

// TestEnumOracles_RequiresKnownValid confirms that "brutus enum oracles" errors at
// flag-validation time when --known-valid is absent. registerOraclesFlags calls
// cmd.MarkFlagRequired("known-valid"), so cobra rejects the invocation before
// RunE / any network call is made.
//
// Pattern mirrors TestEnumTeamsAuth_NoFlagCollisionPanic: redirect rootCmd
// output to io.Discard and restore via t.Cleanup so subsequent tests in the
// package are not affected.
func TestEnumOracles_RequiresKnownValid(t *testing.T) {
	// Redirect cobra output so error text doesn't pollute test output.
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	// Provide --domain so the only missing required flag is --known-valid.
	rootCmd.SetArgs([]string{"enum", "active", "oracles", "--domain", "example.com"})

	// Restore global rootCmd state after the test.
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	err := rootCmd.Execute()

	// cobra must return a non-nil error for the missing required flag.
	require.Error(t, err, "rootCmd.Execute() must return an error when --known-valid is absent")

	// The error message must reference "known-valid" so callers can diagnose
	// which flag is missing. This is the standard cobra required-flag message.
	assert.Contains(t, err.Error(), "known-valid",
		"error message must mention \"known-valid\"; got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// TestEnumOraclesCmd_KnownValidMarkedRequired
// ---------------------------------------------------------------------------

// TestEnumOraclesCmd_KnownValidMarkedRequired asserts — without executing the
// command — that the "known-valid" flag on enumOraclesCmd carries cobra's
// required-flag annotation. This is a static check that complements
// TestEnumOracles_RequiresKnownValid: it verifies registerOraclesFlags calls
// MarkFlagRequired at registration time, independent of command execution.
func TestEnumOraclesCmd_KnownValidMarkedRequired(t *testing.T) {
	f := enumOraclesCmd.Flags().Lookup("known-valid")
	require.NotNil(t, f, "--known-valid flag must exist on enumOraclesCmd")

	annotations := f.Annotations
	_, required := annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, required,
		"--known-valid flag must carry cobra.BashCompOneRequiredFlag annotation (set by MarkFlagRequired)")
}

// ---------------------------------------------------------------------------
// TestAddDomainIndependentOracles
// ---------------------------------------------------------------------------

// TestAddDomainIndependentOracles covers the helper that unions registered
// domain-independent oracles (currently just "github") into the auto-discovered
// oracle slice without duplicating entries that are already present and without
// adding oracles whose plugin is not registered.
func TestAddDomainIndependentOracles(t *testing.T) {
	allRegistered := map[string]bool{
		"microsoft365": true,
		"google":       true,
		"github":       true,
	}
	noGitHub := map[string]bool{
		"microsoft365": true,
		"google":       true,
	}

	tests := []struct {
		name          string
		services      []string
		registeredSet map[string]bool
		// wantContains lists entries that must appear in the result.
		wantContains []string
		// wantGitHubCount is the exact number of times "github" must appear.
		wantGitHubCount int
		// wantLen, when > 0, asserts the exact result length.
		wantLen int
	}{
		{
			name:            "github registered and absent – appended once",
			services:        []string{"microsoft365", "google"},
			registeredSet:   allRegistered,
			wantContains:    []string{"microsoft365", "google", "github"},
			wantGitHubCount: 1,
			wantLen:         3,
		},
		{
			name:            "github registered and already present – not duplicated",
			services:        []string{"github", "google"},
			registeredSet:   allRegistered,
			wantContains:    []string{"github", "google"},
			wantGitHubCount: 1,
			wantLen:         2,
		},
		{
			name:            "github not registered – not added",
			services:        []string{"google"},
			registeredSet:   noGitHub,
			wantContains:    []string{"google"},
			wantGitHubCount: 0,
			wantLen:         1,
		},
		{
			name:            "empty services and github registered – returns [github]",
			services:        []string{},
			registeredSet:   allRegistered,
			wantContains:    []string{"github"},
			wantGitHubCount: 1,
			wantLen:         1,
		},
		{
			name:            "empty services and github not registered – returns empty",
			services:        []string{},
			registeredSet:   noGitHub,
			wantContains:    []string{},
			wantGitHubCount: 0,
			wantLen:         0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Make a copy so the original slice is not mutated between sub-tests.
			input := make([]string, len(tc.services))
			copy(input, tc.services)

			got := addDomainIndependentOracles(input, tc.registeredSet)

			// Assert exact length.
			assert.Len(t, got, tc.wantLen,
				"result length mismatch: got %v", got)

			// Assert all expected entries are present.
			for _, want := range tc.wantContains {
				assert.Contains(t, got, want,
					"result must contain %q; got %v", want, got)
			}

			// Assert "github" appears exactly the expected number of times.
			githubCount := 0
			for _, s := range got {
				if s == "github" {
					githubCount++
				}
			}
			assert.Equal(t, tc.wantGitHubCount, githubCount,
				"\"github\" must appear exactly %d time(s) in result %v",
				tc.wantGitHubCount, got)
		})
	}
}

// ---------------------------------------------------------------------------
// TestEmailDomain
// ---------------------------------------------------------------------------

// TestEmailDomain covers the helper that extracts the domain portion of an
// email address (the substring after the last "@"), used so --domain can
// default to the domain of the required --known-valid email. It confirms the
// normal case, subdomains, the last-"@"-wins rule, and the empty-domain cases
// (no "@", trailing "@", empty string) all resolve as documented.
func TestEmailDomain(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{name: "normal address", email: "admin@example.com", want: "example.com"},
		{name: "subdomain address", email: "a@mail.corp.example.com", want: "mail.corp.example.com"},
		{name: "multiple @ uses the last one", email: `"a@b"@example.com`, want: "example.com"},
		{name: "no @ returns empty", email: "notanemail", want: ""},
		{name: "trailing @ returns empty", email: "user@", want: ""},
		{name: "empty string returns empty", email: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := emailDomain(tc.email)
			assert.Equal(t, tc.want, got,
				"emailDomain(%q) = %q; want %q", tc.email, got, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// TestResolveOraclesDomain
// ---------------------------------------------------------------------------

// TestResolveOraclesDomain covers the helper that decides the effective org
// domain for the oracles command. It confirms the precedence the fix relies on:
// an explicit --domain always wins, and when it is absent the domain is derived
// from the required --known-valid email — so `--known-valid admin@example.com`
// alone yields a domain and satisfies the required-one-of gate. When neither
// yields a domain, it returns "".
func TestResolveOraclesDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		knownValid string
		want       string
	}{
		{
			name:       "explicit domain wins over known-valid",
			domain:     "explicit.com",
			knownValid: "admin@derived.com",
			want:       "explicit.com",
		},
		{
			name:       "explicit domain wins even when known-valid has no domain",
			domain:     "explicit.com",
			knownValid: "notanemail",
			want:       "explicit.com",
		},
		{
			name:       "no domain derives from known-valid",
			domain:     "",
			knownValid: "admin@derived.com",
			want:       "derived.com",
		},
		{
			name:       "no domain and known-valid without @ yields empty",
			domain:     "",
			knownValid: "notanemail",
			want:       "",
		},
		{
			name:       "both empty yields empty",
			domain:     "",
			knownValid: "",
			want:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveOraclesDomain(tc.domain, tc.knownValid)
			assert.Equal(t, tc.want, got,
				"resolveOraclesDomain(%q, %q) = %q; want %q",
				tc.domain, tc.knownValid, got, tc.want)
		})
	}
}
