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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectStdinMode_ExplicitSourcesWin(t *testing.T) {
	origNmap, origMasscan := flagNmapFile, flagMasscanFile
	t.Cleanup(func() {
		flagNmapFile, flagMasscanFile = origNmap, origMasscan
	})
	flagNmapFile, flagMasscanFile = "", ""

	assert.False(t, detectStdinMode("192.168.1.1:22", ""), "--target must disable stdin mode")
	assert.False(t, detectStdinMode("", "targets.txt"), "--targets-file must disable stdin mode")

	flagNmapFile = "scan.xml"
	assert.False(t, detectStdinMode("", ""), "--nmap-file must disable stdin mode")
	flagNmapFile = ""

	flagMasscanFile = "masscan.json"
	assert.False(t, detectStdinMode("", ""), "--masscan-file must disable stdin mode")
}

func TestValidateTargetSources(t *testing.T) {
	origTarget, origFile, origNmap, origMasscan := flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile
	t.Cleanup(func() {
		flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile = origTarget, origFile, origNmap, origMasscan
	})

	flagTarget, flagTargetsFile, flagNmapFile, flagMasscanFile = "", "", "", ""
	require.NoError(t, validateTargetSources(false))
	require.NoError(t, validateTargetSources(true), "stdin alone is valid")

	flagTarget = "host:22"
	require.NoError(t, validateTargetSources(false))

	flagTargetsFile = "targets.txt"
	err := validateTargetSources(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
	assert.Contains(t, err.Error(), "--target")
	assert.Contains(t, err.Error(), "--targets-file")

	flagTarget, flagTargetsFile = "", ""
	flagNmapFile, flagMasscanFile = "a.xml", "b.json"
	err = validateTargetSources(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--nmap-file")
	assert.Contains(t, err.Error(), "--masscan-file")

	flagNmapFile, flagMasscanFile = "", ""
	err = validateTargetSources(true)
	require.NoError(t, err)
	flagTarget = "host:22"
	err = validateTargetSources(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdin")
}

func TestShouldShowBanner(t *testing.T) {
	assert.True(t, shouldShowBanner(false, false, false, true))
	assert.False(t, shouldShowBanner(true, false, false, true), "json output suppresses banner")
	assert.False(t, shouldShowBanner(false, true, false, true), "stdin mode suppresses banner")
	assert.False(t, shouldShowBanner(false, false, true, true), "quiet suppresses banner")
	assert.False(t, shouldShowBanner(false, false, false, false), "no color suppresses banner")
}
