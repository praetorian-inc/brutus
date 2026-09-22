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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldShowBanner(t *testing.T) {
	assert.True(t, shouldShowBanner(false, false, false, true))
	assert.False(t, shouldShowBanner(true, false, false, true), "json output hides banner")
	assert.False(t, shouldShowBanner(false, true, false, true), "stdin mode hides banner")
	assert.False(t, shouldShowBanner(false, false, true, true), "quiet hides banner")
	assert.False(t, shouldShowBanner(false, false, false, false), "no color hides banner")
}

func TestValidateTargetSources(t *testing.T) {
	origTarget, origFile, origNmap, origMasscan := flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile
	t.Cleanup(func() {
		flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile = origTarget, origFile, origNmap, origMasscan
	})

	flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile = "", "", "", ""
	require.NoError(t, validateTargetSources(false))
	require.NoError(t, validateTargetSources(true))

	flagTarget = "10.0.0.1:22"
	require.NoError(t, validateTargetSources(false))

	flagTargetsFile = "hosts.txt"
	err := validateTargetSources(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
	assert.Contains(t, err.Error(), "--target")
	assert.Contains(t, err.Error(), "--targets-file")

	flagTarget, flagTargetsFile = "", ""
	flagNmapFile = "scan.xml"
	require.NoError(t, validateTargetSources(false))
	err = validateTargetSources(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdin")
}

func TestDetectStdinMode(t *testing.T) {
	origNmap, origMasscan := flagNmapFile, flagMasscanFile
	t.Cleanup(func() {
		flagNmapFile, flagMasscanFile = origNmap, origMasscan
	})
	flagNmapFile, flagMasscanFile = "", ""

	assert.False(t, detectStdinMode("10.0.0.1:22", ""))
	assert.False(t, detectStdinMode("", "hosts.txt"))
	flagNmapFile = "scan.xml"
	assert.False(t, detectStdinMode("", ""))
	flagNmapFile = ""
	flagMasscanFile = "masscan.json"
	assert.False(t, detectStdinMode("", ""))
}

func TestSetupAIConfig(t *testing.T) {
	cfg, err := setupAIConfig(false, "", "")
	require.NoError(t, err)
	assert.Nil(t, cfg)

	_, err = setupAIConfig(true, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ANTHROPIC_API_KEY")

	cfg, err = setupAIConfig(true, "claude-key", "")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "claude-vision", cfg.Provider)
	assert.Equal(t, "claude-key", cfg.APIKey)

	cfg, err = setupAIConfig(true, "claude-key", "pplx-key")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "perplexity", cfg.Provider)
	assert.Equal(t, "pplx-key", cfg.APIKey)
}

func TestSetupOutputWriter(t *testing.T) {
	w, forceJSON, cleanup, err := setupOutputWriter("")
	require.NoError(t, err)
	assert.Equal(t, os.Stdout, w)
	assert.False(t, forceJSON)
	cleanup()

	path := filepath.Join(t.TempDir(), "out.json")
	w, forceJSON, cleanup, err = setupOutputWriter(path)
	require.NoError(t, err)
	assert.True(t, forceJSON)
	_, err = w.Write([]byte("ok\n"))
	require.NoError(t, err)
	cleanup()

	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "ok\n", string(body))
}

func TestNervaScanConfig_Defaults(t *testing.T) {
	cfg := nervaScanConfig(&runConfig{baseConfigOptions: &baseConfigOptions{}})
	assert.Equal(t, 5*time.Second, cfg.DefaultTimeout)
	assert.Equal(t, 50, cfg.Workers)
	assert.False(t, cfg.Verbose)

	cfg = nervaScanConfig(&runConfig{baseConfigOptions: &baseConfigOptions{
		timeout: 2 * time.Second,
		threads: 8,
		verbose: true,
	}})
	assert.Equal(t, 2*time.Second, cfg.DefaultTimeout)
	assert.Equal(t, 8, cfg.Workers)
	assert.True(t, cfg.Verbose)
}

func TestDetectTLS(t *testing.T) {
	assert.Equal(t, "verify", detectTLS("verify", true, false))
	assert.Equal(t, "skip-verify", detectTLS("disable", true, false))
	assert.Equal(t, "disable", detectTLS("disable", false, false))
}

func TestIsUnauthOnlyProtocol(t *testing.T) {
	assert.True(t, isUnauthOnlyProtocol("docker"))
	assert.True(t, isUnauthOnlyProtocol("kubernetes"))
	assert.False(t, isUnauthOnlyProtocol("ssh"))
	assert.False(t, isUnauthOnlyProtocol("mqtt"))
}
