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
	"fmt"
	"sort"
	"sync"
)

// =============================================================================
// Plugin Registry
// =============================================================================

var (
	pluginRegistryMu sync.RWMutex
	pluginRegistry   = make(map[string]PluginFactory)
)

// Register adds a plugin factory to the registry.
// This function should be called from plugin init() functions.
// Panics if a plugin with the same name is already registered.
func Register(name string, factory PluginFactory) {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	if _, exists := pluginRegistry[name]; exists {
		panic(fmt.Sprintf("brutus: plugin %q already registered", name))
	}

	pluginRegistry[name] = factory
}

// GetPlugin retrieves a plugin by name and returns a new instance.
// Returns an error if the plugin is not found.
// Each call returns a fresh instance from the factory.
func GetPlugin(name string) (Plugin, error) {
	pluginRegistryMu.RLock()
	factory, exists := pluginRegistry[name]
	pluginRegistryMu.RUnlock()

	if !exists {
		available := ListPlugins()
		return nil, fmt.Errorf("unknown protocol %q (available: %v)", name, available)
	}

	return factory(), nil
}

// ListPlugins returns a sorted list of all registered plugin names.
// The list is sorted to ensure deterministic output in error messages.
func ListPlugins() []string {
	pluginRegistryMu.RLock()
	defer pluginRegistryMu.RUnlock()

	names := make([]string, 0, len(pluginRegistry))
	for name := range pluginRegistry {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// ResetPlugins clears all registered plugins.
// This function is intended for testing only.
func ResetPlugins() {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	pluginRegistry = make(map[string]PluginFactory)
}

// =============================================================================
// Unauth-Only Checker Registry
// =============================================================================

var (
	unauthRegistryMu sync.RWMutex
	unauthRegistry   = make(map[string]func() UnauthOnlyChecker)
)

// RegisterUnauthChecker registers a factory for an unauthenticated-access-only checker.
func RegisterUnauthChecker(name string, factory func() UnauthOnlyChecker) {
	unauthRegistryMu.Lock()
	defer unauthRegistryMu.Unlock()
	if _, exists := unauthRegistry[name]; exists {
		panic(fmt.Sprintf("brutus: unauth checker %q already registered", name))
	}
	unauthRegistry[name] = factory
}

// GetUnauthChecker retrieves an unauth-only checker by name.
func GetUnauthChecker(name string) (UnauthOnlyChecker, error) {
	unauthRegistryMu.RLock()
	factory, exists := unauthRegistry[name]
	unauthRegistryMu.RUnlock()
	if !exists {
		available := ListUnauthCheckers()
		return nil, fmt.Errorf("unknown unauth checker %q (available: %v)", name, available)
	}
	return factory(), nil
}

// ListUnauthCheckers returns a sorted list of all registered unauth-only checker names.
func ListUnauthCheckers() []string {
	unauthRegistryMu.RLock()
	defer unauthRegistryMu.RUnlock()
	names := make([]string, 0, len(unauthRegistry))
	for name := range unauthRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResetUnauthCheckers clears all registered unauth-only checkers.
// This function is intended for testing only.
func ResetUnauthCheckers() {
	unauthRegistryMu.Lock()
	defer unauthRegistryMu.Unlock()
	unauthRegistry = make(map[string]func() UnauthOnlyChecker)
}

// =============================================================================
// Analyzer Registry
// =============================================================================

var (
	analyzerRegistryMu sync.RWMutex
	analyzerRegistry   = make(map[string]AnalyzerFactory)
)

// RegisterAnalyzer registers an analyzer factory for a provider name.
// This is called by analyzer implementations in their init() functions.
func RegisterAnalyzer(provider string, factory AnalyzerFactory) {
	analyzerRegistryMu.Lock()
	defer analyzerRegistryMu.Unlock()
	analyzerRegistry[provider] = factory
}

// GetAnalyzerFactory retrieves the factory for a given provider
func GetAnalyzerFactory(provider string) AnalyzerFactory {
	analyzerRegistryMu.RLock()
	defer analyzerRegistryMu.RUnlock()
	return analyzerRegistry[provider]
}

// ResetAnalyzers clears all registered analyzers.
// This function is intended for testing only.
func ResetAnalyzers() {
	analyzerRegistryMu.Lock()
	defer analyzerRegistryMu.Unlock()
	analyzerRegistry = make(map[string]AnalyzerFactory)
}
