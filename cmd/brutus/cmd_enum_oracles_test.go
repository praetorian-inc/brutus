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
	rootCmd.SetArgs([]string{"enum", "oracles", "--domain", "example.com"})

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
