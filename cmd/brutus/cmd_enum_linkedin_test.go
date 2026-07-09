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
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/praetorian-inc/brutus/pkg/enum/phantombuster"
)

func TestResolvePhantomBusterKey(t *testing.T) {
	tests := []struct {
		name      string
		flagValue string
		envValue  string
		wantKey   string
		wantErr   bool
	}{
		{
			name:      "flag value takes priority over env",
			flagValue: "flag-key",
			envValue:  "env-key",
			wantKey:   "flag-key",
		},
		{
			name:      "env var used when flag is empty",
			flagValue: "",
			envValue:  "env-key",
			wantKey:   "env-key",
		},
		{
			name:      "error when both empty — mentions PHANTOMBUSTER_KEY",
			flagValue: "",
			envValue:  "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PHANTOMBUSTER_KEY", tc.envValue)
			key, err := resolvePhantomBusterKey(tc.flagValue)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "PHANTOMBUSTER_KEY",
					"error message must mention PHANTOMBUSTER_KEY so the operator knows what to set")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

func TestClassifyPhantomBusterError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantContains string
	}{
		{
			name:         "unauthorized",
			err:          pb.ErrUnauthorized,
			wantContains: "invalid or missing API key",
		},
		{
			name:         "not found",
			err:          pb.ErrNotFound,
			wantContains: "agent not found",
		},
		{
			name:         "rate limited",
			err:          pb.ErrRateLimited,
			wantContains: "rate limit exceeded",
		},
		{
			name:         "agent failed",
			err:          pb.ErrAgentFailed,
			wantContains: "agent run failed",
		},
		{
			name:         "unknown error passes through",
			err:          errors.New("network timeout"),
			wantContains: "network timeout",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyPhantomBusterError(tc.err)
			assert.Contains(t, result.Error(), tc.wantContains)
		})
	}
}

func TestEnumLinkedinRegistered(t *testing.T) {
	var passive *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "passive" {
			passive = cmd
			break
		}
	}
	require.NotNil(t, passive, `enumCmd must have a "passive" subcommand`)

	var linkedin *cobra.Command
	for _, cmd := range passive.Commands() {
		if cmd.Use == "linkedin" {
			linkedin = cmd
			break
		}
	}
	require.NotNil(t, linkedin, `"linkedin" must be a subcommand of enumPassiveCmd`)

	for _, flagName := range []string{"agent-id", "api-key", "result-file", "skip-launch"} {
		require.NotNilf(t, linkedin.Flags().Lookup(flagName),
			"--%s flag must exist on linkedin command", flagName)
	}

	agentIDFlag := linkedin.Flags().Lookup("agent-id")
	_, isRequired := agentIDFlag.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, isRequired, "--agent-id must be marked as required")
}

func TestOutputLinkedinHuman_Table(t *testing.T) {
	result := &pb.ScrapeResult{
		Total: 2,
		Profiles: []pb.Profile{
			{
				FullName:    "Jane Doe",
				FirstName:   "Jane",
				LastName:    "Doe",
				Title:       "VP Engineering",
				Company:     "Acme Corp",
				LinkedinURL: "https://linkedin.com/in/janedoe",
				Department:  "Engineering",
			},
			{
				FullName:    "John Smith",
				FirstName:   "John",
				LastName:    "Smith",
				Title:       "CTO",
				Company:     "Widgets Inc",
				LinkedinURL: "https://linkedin.com/in/johnsmith",
			},
		},
	}
	var buf bytes.Buffer
	outputLinkedinHuman(&buf, result, false)
	out := buf.String()

	assert.Contains(t, out, "LinkedIn Sales Navigator")
	assert.Contains(t, out, "Profiles scraped: 2")
	assert.Contains(t, out, "Jane Doe")
	assert.Contains(t, out, "VP Engineering")
	assert.Contains(t, out, "Acme Corp")
	assert.Contains(t, out, "John Smith")
}

func TestOutputLinkedinHuman_Empty(t *testing.T) {
	result := &pb.ScrapeResult{}
	var buf bytes.Buffer
	outputLinkedinHuman(&buf, result, false)
	out := buf.String()
	assert.Contains(t, out, "No profiles found")
}

func TestOutputLinkedinJSONL(t *testing.T) {
	result := &pb.ScrapeResult{
		Total: 1,
		Profiles: []pb.Profile{
			{
				FirstName:          "Jane",
				LastName:           "Doe",
				FullName:           "Jane Doe",
				Title:              "VP Engineering",
				Company:            "Acme Corp",
				LinkedinURL:        "https://linkedin.com/in/janedoe",
				Sources:            []string{"linkedin-salesnav"},
				VerificationStatus: "unverified",
			},
		},
	}
	var buf bytes.Buffer
	outputLinkedinJSONL(&buf, result)
	out := buf.String()

	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.Len(t, lines, 1)
	assert.Contains(t, out, `"type":"linkedin"`)
	assert.Contains(t, out, `"first_name":"Jane"`)
	assert.Contains(t, out, `"linkedin_url":"https://linkedin.com/in/janedoe"`)
	assert.Contains(t, out, `"sources":["linkedin-salesnav"]`)
	assert.Contains(t, out, `"verification_status":"unverified"`)
}
