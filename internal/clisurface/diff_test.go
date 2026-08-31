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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffOfIdenticalSurfacesIsEmpty(t *testing.T) {
	assert.Empty(t, Diff(Walk(newTestTree()), Walk(newTestTree())))
}

func TestDiffReportsARenamedFlagAsOneRemovalAndOneAddition(t *testing.T) {
	documented := Walk(newTestTree())

	tree := newTestTree()
	scan, _, err := tree.Find([]string{"scan"})
	require.NoError(t, err)
	// What a deliberate rename looks like in source: the old flag is gone and
	// an otherwise identical flag is registered under the new name.
	scan.ResetFlags()
	scan.Flags().StringP("host", "t", "", "target host:port")
	registered := Walk(tree)

	findings := Diff(documented, registered)

	require.Len(t, findings, 2, "a rename is exactly one undocumented flag and one removed flag")
	assert.Equal(t, FlagUndocumented, findings[0].Kind)
	assert.Equal(t, "host", findings[0].Flag)
	assert.Equal(t, "tool scan", findings[0].Command)
	assert.Equal(t, FlagRemoved, findings[1].Kind)
	assert.Equal(t, "target", findings[1].Flag)
	assert.Contains(t, findings[0].String(), `flag --host on "tool scan" is registered by cobra but missing from the generated docs`)
	assert.Contains(t, findings[1].String(), `flag --target on "tool scan" is in the generated docs but cobra no longer accepts it`)
}

func TestDiffReportsAddedAndRemovedCommands(t *testing.T) {
	documented := Walk(newTestTree())

	tree := newTestTree()
	tree.AddCommand(&cobra.Command{Use: "brand-new", Short: "new thing", RunE: func(*cobra.Command, []string) error { return nil }})
	scan, _, err := tree.Find([]string{"scan"})
	require.NoError(t, err)
	tree.RemoveCommand(scan)

	findings := Diff(documented, Walk(tree))

	require.Len(t, findings, 2)
	assert.Equal(t, CommandUndocumented, findings[0].Kind)
	assert.Equal(t, "tool brand-new", findings[0].Command)
	assert.Equal(t, CommandRemoved, findings[1].Kind)
	assert.Equal(t, "tool scan", findings[1].Command)
	assert.Contains(t, findings[1].String(), `command "tool scan" is in the generated docs but cobra no longer registers it`)
}

func TestDiffReportsEveryDriftedField(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(c *Command)
		wantField  string
		wantKind   FindingKind
		wantDetail string
	}{
		{
			name:      "short description",
			mutate:    func(c *Command) { c.Short = "reworded" },
			wantField: "short description",
			wantKind:  CommandChanged,
		},
		{
			name:      "aliases",
			mutate:    func(c *Command) { c.Aliases = []string{"sc"} },
			wantField: "aliases",
			wantKind:  CommandChanged,
		},
		{
			name:      "hidden",
			mutate:    func(c *Command) { c.Hidden = true },
			wantField: "hidden",
			wantKind:  CommandChanged,
		},
		{
			name:      "example",
			mutate:    func(c *Command) { c.Example = "different" },
			wantField: "example",
			wantKind:  CommandChanged,
		},
		{
			name:      "flag shorthand",
			mutate:    func(c *Command) { c.Flags[1].Shorthand = "T" },
			wantField: "shorthand",
			wantKind:  FlagChanged,
		},
		{
			name:      "flag default",
			mutate:    func(c *Command) { c.Flags[1].Default = "changed" },
			wantField: "default",
			wantKind:  FlagChanged,
		},
		{
			name:      "flag usability",
			mutate:    func(c *Command) { c.Flags[1].Rejected = true },
			wantField: "rejected by the command",
			wantKind:  FlagChanged,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			documented := Walk(newTestTree())
			registered := Walk(newTestTree())
			cmd, ok := registered.Command("tool scan")
			require.True(t, ok)
			require.Equal(t, "target", cmd.Flags[1].Name, "the fixture's second flag is --target")
			tt.mutate(cmd)

			findings := Diff(documented, registered)

			require.Len(t, findings, 1)
			assert.Equal(t, tt.wantKind, findings[0].Kind)
			assert.Equal(t, tt.wantField, findings[0].Field)
			assert.Equal(t, "tool scan", findings[0].Command)
			assert.Contains(t, findings[0].String(), tt.wantField+" changed from")
		})
	}
}

func TestDiffDetectsARejectionGuardBeingRemoved(t *testing.T) {
	documented := Walk(newTestTree())

	tree := newTestTree()
	guarded, _, err := tree.Find([]string{"guarded"})
	require.NoError(t, err)
	guarded.PreRunE = nil // the guard is deleted

	findings := Diff(documented, Walk(tree))

	require.NotEmpty(t, findings, "dropping the guard changes what the CLI accepts, so it must redden the gate")
	assert.Equal(t, "timeout", findings[0].Flag)
	assert.Equal(t, "tool guarded", findings[0].Command)
	assert.Contains(t, findings[0].String(), "rejected by the command changed from \"true\" (docs) to \"false\" (cobra)")
}

func TestDiffOrdersFindingsByCommandThenFlag(t *testing.T) {
	documented := Walk(newTestTree())
	registered := Walk(newTestTree())

	scan, ok := registered.Command("tool scan")
	require.True(t, ok)
	scan.Flags[2].Default = "changed"
	scan.Flags[0].Default = "changed"
	guarded, ok := registered.Command("tool guarded")
	require.True(t, ok)
	guarded.Flags[0].Default = "changed"

	findings := Diff(documented, registered)

	require.Len(t, findings, 3)
	assert.Equal(t, "tool guarded", findings[0].Command)
	assert.Equal(t, "tool scan", findings[1].Command)
	assert.Equal(t, "json", findings[1].Flag)
	assert.Equal(t, "timeout", findings[2].Flag)
}

func TestReportNamesTheFilesAndTheRegenerationCommand(t *testing.T) {
	findings := []Finding{
		{Kind: FlagRemoved, Command: "brutus logon", Flag: "sticky-keys-exec"},
	}

	report := Report(findings, GeneratedPaths(), RegenerateCommand)

	assert.Contains(t, report, "CLI surface drift: 1 disagreement(s)")
	assert.Contains(t, report, "1. flag --sticky-keys-exec on \"brutus logon\"")
	assert.Contains(t, report, "fix: regenerate docs/cli-surface.json, docs/CLI.md, README.md with 'make cli-docs'")
}

func TestFindingStringForAnUnknownKind(t *testing.T) {
	assert.Equal(t, `something-else: "brutus"`, Finding{Kind: "something-else", Command: "brutus"}.String())
}
