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
)

// Tests that the --rotating-proxy flag is registered only on the GitHub enum
// command (and inherited by its map subcommand), and is NOT a root persistent
// flag or reachable from sibling enum/scan commands. Regression guard for the
// flag move off of rootCmd's persistent flags onto enumGithubCmd.
func TestRotatingProxyFlag_ScopedToGithubEnum(t *testing.T) {
	t.Run("not a root persistent flag", func(t *testing.T) {
		assert.Nil(t, rootCmd.PersistentFlags().Lookup("rotating-proxy"))
	})

	t.Run("present on github enum command", func(t *testing.T) {
		assert.NotNil(t, enumGithubCmd.PersistentFlags().Lookup("rotating-proxy"))
	})

	t.Run("inherited by github map subcommand", func(t *testing.T) {
		assert.NotNil(t, enumGithubMapCmd.InheritedFlags().Lookup("rotating-proxy"))
	})

	t.Run("not reachable from sibling enum command (google)", func(t *testing.T) {
		assert.Nil(t, enumGoogleCmd.InheritedFlags().Lookup("rotating-proxy"))
		assert.Nil(t, enumGoogleCmd.Flags().Lookup("rotating-proxy"))
	})

	t.Run("not reachable from scan command (creds)", func(t *testing.T) {
		assert.Nil(t, credsCmd.InheritedFlags().Lookup("rotating-proxy"))
		assert.Nil(t, credsCmd.Flags().Lookup("rotating-proxy"))
	})
}
