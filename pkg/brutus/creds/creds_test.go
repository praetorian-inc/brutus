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

package creds

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsCredsProtocol(t *testing.T) {
	// Creds protocols
	assert.True(t, IsCredsProtocol("ssh"))
	assert.True(t, IsCredsProtocol("mysql"))
	assert.True(t, IsCredsProtocol("rdp"))
	assert.True(t, IsCredsProtocol("ldap"))

	// SNMP has its own subcommand (should return false)
	assert.False(t, IsCredsProtocol("snmp"))

	// Web protocols (should return false)
	assert.False(t, IsCredsProtocol("http"))
	assert.False(t, IsCredsProtocol("https"))
	assert.False(t, IsCredsProtocol("browser"))
}
