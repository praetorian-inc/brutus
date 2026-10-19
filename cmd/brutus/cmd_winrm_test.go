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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectWinRMHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	require.NoError(t, os.WriteFile(path, []byte("10.0.0.1\n# skip\n10.0.0.2:5986\n\n"), 0o644))

	flagTarget = "10.0.0.3"
	flagTargetsFile = path
	t.Cleanup(func() {
		flagTarget = ""
		flagTargetsFile = ""
	})

	hosts, err := collectWinRMHosts()
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2:5986", "10.0.0.3"}, hosts)
}

func TestCollectWinRMHostsMissing(t *testing.T) {
	flagTarget = ""
	flagTargetsFile = ""
	_, err := collectWinRMHosts()
	require.Error(t, err)
}

func TestWinRMCommandRegistered(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"winrm"})
	require.NoError(t, err)
	assert.Equal(t, "winrm", cmd.Name())
}
