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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestHasSecurityFinding(t *testing.T) {
	assert.True(t, hasSecurityFinding("[CRITICAL] Redis accessible without authentication"))
	assert.True(t, hasSecurityFinding("[HIGH] Sticky keys backdoor enabled"))
	assert.True(t, hasSecurityFinding("[INFO] Sticky keys set, Utilman not"))
	assert.False(t, hasSecurityFinding("[INFO] banner grabbed"))
	assert.False(t, hasSecurityFinding("[MEDIUM] weak cipher"))
	assert.False(t, hasSecurityFinding(""))
	assert.False(t, hasSecurityFinding("login successful"))
}

func TestEmitSecurityFindings_Uncolored(t *testing.T) {
	out := captureStdout(t, func() {
		emitSecurityFindings([]brutus.Result{
			{Protocol: "ssh", Target: "10.0.0.1:22", Banner: "OpenSSH_8.2"},
			{Protocol: "redis", Target: "10.0.0.1:6379", Banner: "[CRITICAL] Redis accessible without authentication"},
			{Protocol: "docker", Target: "10.0.0.1:2375", Banner: "[CRITICAL] Docker daemon API exposed without authentication"},
		}, false)
	})
	assert.Contains(t, out, "redis @ 10.0.0.1:6379: [CRITICAL] Redis accessible without authentication")
	assert.NotContains(t, out, "docker")
	assert.NotContains(t, out, "OpenSSH")
}

func TestEmitSecurityFindings_NoMatch(t *testing.T) {
	out := captureStdout(t, func() {
		emitSecurityFindings([]brutus.Result{
			{Protocol: "ssh", Target: "10.0.0.1:22", Banner: ""},
			{Protocol: "ftp", Target: "10.0.0.1:21", Banner: "220 ready"},
		}, false)
	})
	assert.Empty(t, out)
}

func TestEmitSecurityFindings_ColoredHeading(t *testing.T) {
	out := captureStdout(t, func() {
		emitSecurityFindings([]brutus.Result{
			{Protocol: "rdp", Target: "10.0.0.5:3389", Banner: "[INFO] Sticky keys backdoor detected\nUtilman: yes"},
		}, true)
	})
	assert.Contains(t, out, "Security Findings")
	assert.Contains(t, out, "rdp @ 10.0.0.5:3389")
	assert.Contains(t, out, "[INFO] Sticky keys backdoor detected")
	assert.Contains(t, out, "Utilman: yes")
}

func TestSplitLines_SkipsEmpty(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, splitLines("a\n\nb\n"))
	assert.Nil(t, splitLines(""))
	assert.Equal(t, []string{"only"}, splitLines("only"))
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
