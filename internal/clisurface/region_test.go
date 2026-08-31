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

// docWithRegion builds a small document carrying one generated region.
func docWithRegion(name, body string) string {
	return strings.Join([]string{
		"# Title",
		"",
		BeginMarker(name),
		body,
		EndMarker(name),
		"",
		"hand-written tail",
		"",
	}, "\n")
}

func TestSpliceReplacesOnlyTheRegionBody(t *testing.T) {
	doc := docWithRegion("cli-subcommands", "stale body")

	out, err := Splice(doc, "cli-subcommands", "fresh body")
	require.NoError(t, err)

	assert.Equal(t, docWithRegion("cli-subcommands", "fresh body"), out)
	assert.Contains(t, out, "hand-written tail", "text outside the region is untouched")
}

func TestSpliceIsIdempotent(t *testing.T) {
	doc := docWithRegion("cli-aliases", "old")

	once, err := Splice(doc, "cli-aliases", "new\nlines\n")
	require.NoError(t, err)
	twice, err := Splice(once, "cli-aliases", "new\nlines\n")
	require.NoError(t, err)

	assert.Equal(t, once, twice, "splicing the same body twice must converge")
	assert.NotContains(t, once, "new\n\n</", "the body keeps exactly one trailing newline")
}

func TestRegionBodyRoundTrips(t *testing.T) {
	doc := docWithRegion("cli-aliases", "line one\nline two")

	body, err := RegionBody(doc, "cli-aliases")
	require.NoError(t, err)
	assert.Equal(t, "line one\nline two\n", body)
}

func TestSpliceRejectsBrokenMarkers(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name:    "missing begin marker",
			doc:     "text\n" + EndMarker("cli-aliases") + "\n",
			wantErr: `expected exactly one "<!-- BEGIN generated: cli-aliases -->" marker, found 0`,
		},
		{
			name:    "missing end marker",
			doc:     BeginMarker("cli-aliases") + "\nbody\n",
			wantErr: `expected exactly one "<!-- END generated: cli-aliases -->" marker, found 0`,
		},
		{
			name:    "duplicated region",
			doc:     docWithRegion("cli-aliases", "a") + docWithRegion("cli-aliases", "b"),
			wantErr: "found 2",
		},
		{
			name:    "markers out of order",
			doc:     EndMarker("cli-aliases") + "\nbody\n" + BeginMarker("cli-aliases") + "\n",
			wantErr: "appears before",
		},
		{
			name:    "begin marker not on its own line",
			doc:     BeginMarker("cli-aliases") + " trailing text without newline" + EndMarker("cli-aliases"),
			wantErr: "must be followed by a newline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Splice(tt.doc, "cli-aliases", "body")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMarkersAreHTMLComments(t *testing.T) {
	assert.Equal(t, "<!-- BEGIN generated: cli-subcommands -->", BeginMarker(RegionSubcommands))
	assert.Equal(t, "<!-- END generated: cli-aliases -->", EndMarker(RegionAliases))
}

// TestSpliceRejectsMarkersOnOneLine pins the bounds guard. Both markers on a single line
// used to splice into a document carrying a duplicated closing marker instead of failing.
func TestSpliceRejectsMarkersOnOneLine(t *testing.T) {
	doc := BeginMarker(RegionSubcommands) + " " + EndMarker(RegionSubcommands) + "\n"

	_, err := Splice(doc, RegionSubcommands, "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "separate lines")
}
