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

// Package google_test is the external test package for internal/enumplugins/google.
// It is restricted to offline-safe assertions about the plugin's registration
// and name — behavioral (mock-server) coverage now lives in pkg/enum/google
// where the unexported base URL fields are accessible.
package google_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"

	// Side-effect import: triggers the init() that registers the "google" plugin.
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/google"
)

// TestPlugin_RegistrationAndName verifies that the plugin's init() registers
// "google" in the enum registry and that the resulting instance reports the
// correct name. No network calls are made.
func TestPlugin_RegistrationAndName(t *testing.T) {
	t.Parallel()

	p, err := enum.GetPlugin("google")
	require.NoError(t, err, "enum.GetPlugin(\"google\") must succeed — plugin must be registered via init()")
	require.NotNil(t, p, "returned plugin must be non-nil")
	assert.Equal(t, "google", p.Name(), "plugin Name() must return \"google\"")
}
