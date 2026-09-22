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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerate_RegistryFanOut(t *testing.T) {
	name := fmt.Sprintf("test-workers-%d", time.Now().UnixNano())
	Register(name, func() Plugin {
		return &stubPlugin{name: name, exists: true}
	})

	results, err := Enumerate(&Config{
		Emails:   []string{"a@example.com", "b@example.com"},
		Services: []string{name},
		Threads:  2,
		Timeout:  time.Second,
	})
	require.NoError(t, err)
	require.Len(t, results, 2)

	got := map[string]Result{}
	for _, r := range results {
		got[r.Email] = r
		assert.Equal(t, name, r.Service)
		assert.True(t, r.Exists)
	}
	assert.Contains(t, got, "a@example.com")
	assert.Contains(t, got, "b@example.com")
}

func TestEnumerate_UnknownService(t *testing.T) {
	_, err := Enumerate(&Config{
		Emails:   []string{"a@example.com"},
		Services: []string{"no-such-enum-service-xyz"},
		Timeout:  time.Second,
		Threads:  1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving service")
	assert.Contains(t, err.Error(), "no-such-enum-service-xyz")
}

func TestEnumerate_EmailsRequired(t *testing.T) {
	_, err := Enumerate(&Config{Services: []string{"unused"}, Threads: 1})
	require.Error(t, err)
	assert.Equal(t, "emails required", err.Error())
}

func TestEnumerate_InvalidProxy(t *testing.T) {
	name := fmt.Sprintf("test-workers-proxy-%d", time.Now().UnixNano())
	Register(name, func() Plugin {
		return &stubPlugin{name: name, exists: true}
	})

	_, err := Enumerate(&Config{
		Emails:   []string{"a@example.com"},
		Services: []string{name},
		ProxyURL: "://bad",
		Timeout:  time.Second,
		Threads:  1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuring enum HTTP client")
}
