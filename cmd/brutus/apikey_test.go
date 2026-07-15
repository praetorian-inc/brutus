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

func TestResolveAPIKey(t *testing.T) {
	const testEnvVar = "BRUTUS_TEST_API_KEY"

	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv(testEnvVar, "env-value")

		key, err := resolveAPIKey("flag-value", testEnvVar, "testprovider")

		require.NoError(t, err)
		assert.Equal(t, "flag-value", key)
	})

	t.Run("falls back to env when flag empty", func(t *testing.T) {
		t.Setenv(testEnvVar, "env-value")

		key, err := resolveAPIKey("", testEnvVar, "testprovider")

		require.NoError(t, err)
		assert.Equal(t, "env-value", key)
	})

	t.Run("errors when neither flag nor env set", func(t *testing.T) {
		t.Setenv("HUNTER_API_KEY", "")

		key, err := resolveAPIKey("", "HUNTER_API_KEY", "hunter.io")

		require.Error(t, err)
		assert.Equal(t, "hunter.io API key required: set HUNTER_API_KEY or pass --api-key", err.Error())
		assert.Empty(t, key)
	})
}
