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

package brutus

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type registryStubPlugin struct {
	name string
	id   int
}

func (s *registryStubPlugin) Name() string { return s.name }

func (s *registryStubPlugin) Test(context.Context, string, string, string, time.Duration, PluginConfig) *Result {
	return &Result{Protocol: s.name}
}

type registryStubUnauth struct{ name string }

func (s *registryStubUnauth) Name() string { return s.name }

func (s *registryStubUnauth) CheckUnauth(context.Context, string, time.Duration, PluginConfig) *Result {
	return &Result{Protocol: s.name, Success: true}
}

type registryStubAnalyzer struct{}

func (s *registryStubAnalyzer) Analyze(context.Context, BannerInfo) ([]string, error) {
	return []string{"admin:admin"}, nil
}

func uniqueRegistryName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestGetPlugin_Unknown(t *testing.T) {
	_, err := GetPlugin("no-such-protocol-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown protocol")
	assert.Contains(t, err.Error(), "available")
}

func TestRegisterGetListPlugins(t *testing.T) {
	name := uniqueRegistryName("test-plugin")
	var nextID int
	Register(name, func() Plugin {
		nextID++
		return &registryStubPlugin{name: name, id: nextID}
	})

	p, err := GetPlugin(name)
	require.NoError(t, err)
	assert.Equal(t, name, p.Name())

	// Each GetPlugin call must return a fresh instance from the factory.
	a, err := GetPlugin(name)
	require.NoError(t, err)
	b, err := GetPlugin(name)
	require.NoError(t, err)
	assert.NotSame(t, a, b)

	listed := ListPlugins()
	assert.True(t, sort.StringsAreSorted(listed))
	assert.Contains(t, listed, name)
}

func TestRegister_DuplicatePanics(t *testing.T) {
	name := uniqueRegistryName("test-dup")
	Register(name, func() Plugin {
		return &registryStubPlugin{name: name}
	})
	assert.Panics(t, func() {
		Register(name, func() Plugin {
			return &registryStubPlugin{name: name}
		})
	})
}

func TestResetPlugins(t *testing.T) {
	name := uniqueRegistryName("test-reset")
	Register(name, func() Plugin {
		return &registryStubPlugin{name: name}
	})
	_, err := GetPlugin(name)
	require.NoError(t, err)

	ResetPlugins()
	_, err = GetPlugin(name)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown protocol")
	assert.Empty(t, ListPlugins())
}

func TestGetUnauthChecker_Unknown(t *testing.T) {
	_, err := GetUnauthChecker("no-such-unauth-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown unauth checker")
	assert.Contains(t, err.Error(), "available")
}

func TestRegisterGetListUnauthCheckers(t *testing.T) {
	name := uniqueRegistryName("test-unauth")
	RegisterUnauthChecker(name, func() UnauthOnlyChecker {
		return &registryStubUnauth{name: name}
	})

	c, err := GetUnauthChecker(name)
	require.NoError(t, err)
	assert.Equal(t, name, c.Name())

	listed := ListUnauthCheckers()
	assert.True(t, sort.StringsAreSorted(listed))
	assert.Contains(t, listed, name)
}

func TestRegisterUnauthChecker_DuplicatePanics(t *testing.T) {
	name := uniqueRegistryName("test-unauth-dup")
	RegisterUnauthChecker(name, func() UnauthOnlyChecker {
		return &registryStubUnauth{name: name}
	})
	assert.Panics(t, func() {
		RegisterUnauthChecker(name, func() UnauthOnlyChecker {
			return &registryStubUnauth{name: name}
		})
	})
}

func TestResetUnauthCheckers(t *testing.T) {
	name := uniqueRegistryName("test-unauth-reset")
	RegisterUnauthChecker(name, func() UnauthOnlyChecker {
		return &registryStubUnauth{name: name}
	})
	_, err := GetUnauthChecker(name)
	require.NoError(t, err)

	ResetUnauthCheckers()
	_, err = GetUnauthChecker(name)
	require.Error(t, err)
	assert.Empty(t, ListUnauthCheckers())
}

func TestGetAnalyzerFactory_Unknown(t *testing.T) {
	assert.Nil(t, GetAnalyzerFactory("no-such-analyzer-xyz"))
}

func TestRegisterGetAnalyzerFactory(t *testing.T) {
	name := uniqueRegistryName("test-analyzer")
	RegisterAnalyzer(name, func(cfg *LLMConfig) BannerAnalyzer {
		assert.NotNil(t, cfg)
		return &registryStubAnalyzer{}
	})

	factory := GetAnalyzerFactory(name)
	require.NotNil(t, factory)
	analyzer := factory(&LLMConfig{Enabled: true, Provider: name})
	require.NotNil(t, analyzer)
	creds, err := analyzer.Analyze(context.Background(), BannerInfo{})
	require.NoError(t, err)
	assert.Equal(t, []string{"admin:admin"}, creds)
}

func TestRegisterAnalyzer_Overwrites(t *testing.T) {
	name := uniqueRegistryName("test-analyzer-overwrite")
	RegisterAnalyzer(name, func(*LLMConfig) BannerAnalyzer {
		return nil
	})
	RegisterAnalyzer(name, func(*LLMConfig) BannerAnalyzer {
		return &registryStubAnalyzer{}
	})

	factory := GetAnalyzerFactory(name)
	require.NotNil(t, factory)
	assert.NotNil(t, factory(&LLMConfig{}))
}

func TestResetAnalyzers(t *testing.T) {
	name := uniqueRegistryName("test-analyzer-reset")
	RegisterAnalyzer(name, func(*LLMConfig) BannerAnalyzer {
		return &registryStubAnalyzer{}
	})
	require.NotNil(t, GetAnalyzerFactory(name))

	ResetAnalyzers()
	assert.Nil(t, GetAnalyzerFactory(name))
}
