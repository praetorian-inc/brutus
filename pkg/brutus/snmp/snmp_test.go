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

package snmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSNMPProtocol(t *testing.T) {
	assert.True(t, IsSNMPProtocol("snmp"))
	assert.False(t, IsSNMPProtocol("ssh"))
	assert.False(t, IsSNMPProtocol("http"))
	assert.False(t, IsSNMPProtocol(""))
}

func TestConfigureSNMP(t *testing.T) {
	strings, err := ConfigureSNMP("default")
	require.NoError(t, err)
	assert.NotEmpty(t, strings)
	assert.Contains(t, strings, "public")

	strings, err = ConfigureSNMP("extended")
	require.NoError(t, err)
	assert.True(t, len(strings) > 20)

	strings, err = ConfigureSNMP("full")
	require.NoError(t, err)
	assert.True(t, len(strings) > 50)

	_, err = ConfigureSNMP("invalid")
	assert.Error(t, err)
}
