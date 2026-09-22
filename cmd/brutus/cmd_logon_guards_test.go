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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus/logon"
)

func TestRunLogonChecks_OpenRequiresWeb(t *testing.T) {
	origOpen, origWeb := flagOpen, flagWeb
	t.Cleanup(func() {
		flagOpen, flagWeb = origOpen, origWeb
	})
	flagOpen, flagWeb = true, false

	err := runLogonChecks(logonCmd, logon.CheckBoth)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--open requires --web")
}

func TestInteractionExitError(t *testing.T) {
	assert.NoError(t, interactionExitError(&logon.InteractionResult{
		Target:    "10.0.0.1:3389",
		Mode:      logon.InteractionExec,
		Succeeded: true,
	}))

	err := interactionExitError(&logon.InteractionResult{
		Target:    "10.0.0.1:3389",
		Mode:      logon.InteractionExec,
		Succeeded: false,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backdoor not reached")

	want := errors.New("dial failed")
	got := interactionExitError(&logon.InteractionResult{Err: want})
	assert.Equal(t, want, got)
}
