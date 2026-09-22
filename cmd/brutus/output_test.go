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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestHasSecurityFinding(t *testing.T) {
	assert.True(t, hasSecurityFinding("[CRITICAL] open redis"))
	assert.True(t, hasSecurityFinding("[HIGH] sticky keys"))
	assert.True(t, hasSecurityFinding("[INFO] Sticky keys backdoor"))
	assert.False(t, hasSecurityFinding(""))
	assert.False(t, hasSecurityFinding("SSH-2.0-OpenSSH_8.9"))
}

func TestSplitLines(t *testing.T) {
	assert.Empty(t, splitLines(""))
	assert.Equal(t, []string{"a", "b"}, splitLines("a\n\nb\n"))
	assert.Equal(t, []string{"only"}, splitLines("only"))
}

func TestOutputJSONL_CredentialsAndFindings(t *testing.T) {
	var buf bytes.Buffer
	outputJSONL(&buf, []brutus.Result{
		{Protocol: "ssh", Target: "10.0.0.1:22", Username: "root", Password: "toor", Success: true, Duration: time.Millisecond},
		{Protocol: "ssh", Target: "10.0.0.1:22", Username: "root", Password: "wrong", Success: false},
		{Protocol: "redis", Target: "10.0.0.2:6379", Username: "(unauthenticated)", Success: true, Banner: "[CRITICAL] Redis accessible without authentication"},
		{Protocol: "rdp", Target: "10.0.0.3:3389", Success: false, Banner: "[INFO] Sticky keys detected"},
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3)

	var cred map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &cred))
	assert.Equal(t, "ssh", cred["protocol"])
	assert.Equal(t, "root", cred["username"])
	assert.Equal(t, "toor", cred["password"])
	assert.NotContains(t, cred, "finding")

	var unauth map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &unauth))
	assert.Equal(t, "unauthenticated_access", unauth["finding"])
	assert.Equal(t, "redis", unauth["protocol"])

	var finding map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &finding))
	assert.Equal(t, "security", finding["finding"])
	assert.Equal(t, "rdp", finding["protocol"])
}

func TestOutputValidOnly(t *testing.T) {
	out := captureStdout(t, func() {
		outputValidOnly([]brutus.Result{
			{Protocol: "ssh", Target: "host:22", Username: "root", Password: "toor", Success: true},
			{Protocol: "ssh", Target: "host:22", Username: "root", Password: "nope", Success: false},
			{Protocol: "redis", Target: "host:6379", Username: "(unauthenticated)", Success: true, Banner: "[CRITICAL] open"},
			{Protocol: "ssh", Target: "host:22", Username: "deploy", Key: []byte("key"), Success: true},
		}, false)
	})
	assert.Contains(t, out, "ssh root:toor@host:22")
	assert.Contains(t, out, "ssh deploy:key@host:22")
	assert.NotContains(t, out, "nope")
	assert.NotContains(t, out, "unauthenticated")
}

func TestOutputHuman_SkipsUnauthCredentials(t *testing.T) {
	out := captureStdout(t, func() {
		outputHuman([]brutus.Result{
			{Protocol: "ssh", Target: "host:22", Username: "root", Password: "toor", Success: true, Duration: time.Millisecond},
			{Protocol: "redis", Target: "host:6379", Username: "(unauthenticated)", Success: true, Banner: "[CRITICAL] Redis open"},
			{Protocol: "ssh", Target: "host:22", Username: "root", Password: "x", Success: false, Error: errors.New("connection error")},
		}, false, false)
	})
	assert.Contains(t, out, "[+] VALID: ssh root:toor @ host:22")
	assert.Contains(t, out, "Security Findings")
	assert.Contains(t, out, "[CRITICAL] Redis open")
	assert.Contains(t, out, "1 valid")
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
