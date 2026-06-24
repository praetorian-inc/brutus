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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum/harvest"
	// Blank import ensures all 5 sources are registered (bing, brave, crtsh, ddg, yahoo)
	// before TestHarvestSourcesAllRegistered runs.
	_ "github.com/praetorian-inc/brutus/pkg/enum/harvest/sources"
)

// ---------------------------------------------------------------------------
// Task 9: outputHarvestJSONL + outputHarvestHuman
// ---------------------------------------------------------------------------

func TestOutputHarvestJSONL(t *testing.T) {
	rep := &harvest.Report{
		Domain: "acme.com",
		Hits: []harvest.EmailHit{
			{Email: "jane@acme.com", Sources: []string{"bing", "crtsh"}, Count: 2},
		},
	}
	var buf bytes.Buffer
	outputHarvestJSONL(&buf, rep)

	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &obj))
	assert.Equal(t, "harvest", obj["type"])
	assert.Equal(t, "jane@acme.com", obj["email"])
	assert.Equal(t, float64(2), obj["count"])
	assert.Equal(t, "acme.com", obj["domain"])
}

func TestOutputHarvestJSONLMultipleHits(t *testing.T) {
	rep := &harvest.Report{
		Domain: "acme.com",
		Hits: []harvest.EmailHit{
			{Email: "alice@acme.com", Sources: []string{"bing", "crtsh"}, Count: 2},
			{Email: "bob@acme.com", Sources: []string{"ddg"}, Count: 1},
		},
	}
	var buf bytes.Buffer
	outputHarvestJSONL(&buf, rep)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2, "expected 2 JSONL lines")

	for _, line := range lines {
		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj))
		assert.Equal(t, "harvest", obj["type"], "type field must be 'harvest'")
	}
}

func TestOutputHarvestJSONLEmptyReport(t *testing.T) {
	rep := &harvest.Report{Domain: "acme.com", Hits: nil}
	var buf bytes.Buffer
	outputHarvestJSONL(&buf, rep)
	assert.Empty(t, strings.TrimSpace(buf.String()), "empty report should produce no JSONL lines")
}

func TestOutputHarvestHuman(t *testing.T) {
	rep := &harvest.Report{
		Domain: "acme.com",
		Hits: []harvest.EmailHit{
			{Email: "jane@acme.com", Sources: []string{"bing"}, Count: 1},
		},
	}
	var buf bytes.Buffer
	outputHarvestHuman(&buf, rep, false)
	out := buf.String()

	assert.Contains(t, out, "jane@acme.com")
	assert.Contains(t, out, "Email")
}

func TestOutputHarvestHumanEmpty(t *testing.T) {
	rep := &harvest.Report{Domain: "acme.com", Hits: nil}
	var buf bytes.Buffer
	outputHarvestHuman(&buf, rep, false)
	out := buf.String()

	// Must contain some indication that no emails were found.
	assert.Contains(t, out, "No emails found")
}

func TestOutputHarvestHumanCorroborated(t *testing.T) {
	rep := &harvest.Report{
		Domain: "acme.com",
		Hits: []harvest.EmailHit{
			{Email: "alice@acme.com", Sources: []string{"bing", "crtsh"}, Count: 2},
			{Email: "bob@acme.com", Sources: []string{"ddg"}, Count: 1},
		},
	}
	var buf bytes.Buffer
	outputHarvestHuman(&buf, rep, false)
	out := buf.String()

	assert.Contains(t, out, "alice@acme.com")
	assert.Contains(t, out, "bob@acme.com")
	// The header line should mention the corroboration count.
	assert.Contains(t, out, "corroborated")
}

// ---------------------------------------------------------------------------
// Task 10: subcommand registration
// ---------------------------------------------------------------------------

func TestEnumHarvestRegistered(t *testing.T) {
	var found bool
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use != "harvest" {
			continue
		}
		found = true

		require.NotNil(t, cmd.Flags().Lookup("domain"), "--domain flag must exist")
		require.NotNil(t, cmd.Flags().Lookup("sources"), "--sources flag must exist")
		require.NotNil(t, cmd.Flags().Lookup("limit"), "--limit flag must exist")

		// Verify -d shorthand exists.
		require.NotNil(t, cmd.Flags().ShorthandLookup("d"), "-d shorthand must exist")

		// Verify --domain is marked required via cobra annotation.
		_, isReq := cmd.Flags().Lookup("domain").Annotations["cobra_annotation_bash_completion_one_required_flag"]
		assert.True(t, isReq, "--domain must be marked as required")
		break
	}
	require.True(t, found, "harvest subcommand must be registered")
}

func TestHarvestSourcesAllRegistered(t *testing.T) {
	got := harvest.ListSources()
	for _, want := range []string{"bing", "brave", "crtsh", "ddg", "yahoo"} {
		assert.Contains(t, got, want, "source %q must be registered via blank import", want)
	}
}
