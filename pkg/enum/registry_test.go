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

package enum

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPlugin_Unknown(t *testing.T) {
	_, err := GetPlugin("no-such-service-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
	assert.Contains(t, err.Error(), "available")
}

func TestRegisterGetList(t *testing.T) {
	name := fmt.Sprintf("test-registry-%d", time.Now().UnixNano())
	Register(name, func() Plugin {
		return &stubPlugin{name: name, exists: true}
	})

	p, err := GetPlugin(name)
	require.NoError(t, err)
	assert.Equal(t, name, p.Name())

	listed := ListPlugins()
	assert.True(t, sort.StringsAreSorted(listed))
	assert.Contains(t, listed, name)
}

func TestRegister_DuplicatePanics(t *testing.T) {
	name := fmt.Sprintf("test-dup-%d", time.Now().UnixNano())
	Register(name, func() Plugin {
		return &stubPlugin{name: name}
	})
	assert.Panics(t, func() {
		Register(name, func() Plugin {
			return &stubPlugin{name: name}
		})
	})
}
