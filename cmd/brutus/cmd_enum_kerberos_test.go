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
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kerberos "github.com/praetorian-inc/brutus/pkg/enum/kerberos"
)

func TestEnumKerberosRegistered(t *testing.T) {
	var active *cobra.Command
	for _, cmd := range enumCmd.Commands() {
		if cmd.Use == "active" {
			active = cmd
			break
		}
	}
	require.NotNil(t, active, `enumCmd must have an "active" subcommand`)

	var kerb *cobra.Command
	for _, cmd := range active.Commands() {
		if cmd.Use == "kerberos" {
			kerb = cmd
			break
		}
	}
	require.NotNil(t, kerb, `"kerberos" must be a subcommand of enum active`)

	for _, name := range []string{"dc", "users", "user-file", "domain"} {
		require.NotNilf(t, kerb.Flags().Lookup(name), "--%s must exist", name)
	}
	dc := kerb.Flags().Lookup("dc")
	_, dcRequired := dc.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, dcRequired, "--dc must be marked required")

	domain := kerb.Flags().Lookup("domain")
	_, domainRequired := domain.Annotations["cobra_annotation_bash_completion_one_required_flag"]
	assert.True(t, domainRequired, "--domain must be marked required")
}

func TestRunEnumKerberos_NoUsernames(t *testing.T) {
	origUsers, origFile := flagKerbUsers, flagKerbUserFile
	t.Cleanup(func() {
		flagKerbUsers, flagKerbUserFile = origUsers, origFile
	})
	flagKerbUsers, flagKerbUserFile = "", ""

	err := runEnumKerberos(enumKerberosCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usernames")
}

func TestOutputKerberosJSONL(t *testing.T) {
	var buf bytes.Buffer
	outputKerberosJSONL(&buf, []*kerberos.Result{
		{Username: "administrator", Realm: "CORP.LOCAL", Exists: true, NoPreAuth: true, Duration: time.Millisecond},
		{Username: "guest", Realm: "CORP.LOCAL", Exists: true, Annotation: "disabled", Duration: 2 * time.Millisecond},
		{Username: "missing", Realm: "CORP.LOCAL", Exists: false, Duration: time.Millisecond},
		{Username: "broken", Realm: "CORP.LOCAL", Error: errors.New("timeout"), Duration: time.Millisecond},
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 4)

	var roast map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &roast))
	assert.Equal(t, "kerberos_enum", roast["type"])
	assert.Equal(t, "administrator", roast["username"])
	assert.Equal(t, true, roast["exists"])
	assert.Equal(t, true, roast["no_preauth"])
	assert.NotContains(t, roast, "annotation")

	var disabled map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &disabled))
	assert.Equal(t, "disabled", disabled["annotation"])
	assert.Equal(t, true, disabled["exists"])

	var missing map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &missing))
	assert.Equal(t, false, missing["exists"])
	assert.NotContains(t, missing, "no_preauth")

	var broken map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[3]), &broken))
	assert.Equal(t, "timeout", broken["error"])
}

func TestOutputKerberosHuman(t *testing.T) {
	origQuiet := flagQuiet
	flagQuiet = false
	t.Cleanup(func() { flagQuiet = origQuiet })

	out := captureStdout(t, func() {
		outputKerberosHuman([]*kerberos.Result{
			{Username: "administrator", Exists: true, NoPreAuth: true, Duration: time.Millisecond},
			{Username: "guest", Exists: true, Annotation: "disabled", Duration: time.Millisecond},
			{Username: "missing", Exists: false, Duration: time.Millisecond},
			{Username: "broken", Error: errors.New("timeout"), Duration: time.Millisecond},
		}, false)
	})
	assert.Contains(t, out, "EXISTS")
	assert.Contains(t, out, "AS-REP roastable")
	assert.Contains(t, out, "disabled")
	assert.Contains(t, out, "NOT FOUND")
	assert.Contains(t, out, "ERROR")
	assert.Contains(t, out, "Exists:      2")
	assert.Contains(t, out, "Not found:   1")
	assert.Contains(t, out, "Errors:      1")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}
