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

// TestBuildBaseConfig_ProxyUserWithoutProxy is a fail-closed regression test at
// the cmd layer: passing --proxy-user without --proxy must cause buildBaseConfig
// to return a non-nil error (not a silent direct connection).
//
// This guards against regressions where resolveProxyURL inside buildBaseConfig
// accepts a proxy-user-only configuration and silently degrades to a direct
// connection, leaking credentials or bypassing the intended proxy path.
func TestBuildBaseConfig_ProxyUserWithoutProxy(t *testing.T) {
	// Save and restore the package-level proxy flag vars so this test does not
	// bleed state into parallel tests.
	origProxy := flagProxy
	origProxyUser := flagProxyUser
	t.Cleanup(func() {
		flagProxy = origProxy
		flagProxyUser = origProxyUser
	})

	// Simulate --proxy-user set, --proxy empty (the misconfigured case).
	flagProxy = ""
	flagProxyUser = "u:p"

	// buildBaseConfig reads proxy state via resolveProxyURL(), which calls
	// brutus.BuildProxyURL(flagProxy, flagProxyUser). With a non-empty proxyUser
	// and an empty proxyURL that function must return an error.
	base, err := buildBaseConfig(logonCmd)

	require.Error(t, err,
		"buildBaseConfig must return an error when --proxy-user is set without --proxy")
	assert.Nil(t, base,
		"buildBaseConfig must return nil options on proxy misconfiguration")
	assert.Contains(t, err.Error(), "requires",
		"error message must contain 'requires' to explain the constraint")
}
