// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// pkg/enum/registry.go
package enum

import (
	"fmt"
	"sort"
	"sync"
)

var (
	pluginRegistryMu sync.RWMutex
	pluginRegistry   = make(map[string]PluginFactory)
)

// Register adds an enum plugin factory to the registry.
// Called from plugin init() functions. Panics if duplicate.
func Register(name string, factory PluginFactory) {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	if _, exists := pluginRegistry[name]; exists {
		panic(fmt.Sprintf("enum: plugin %q already registered", name))
	}

	pluginRegistry[name] = factory
}

// GetPlugin retrieves an enum plugin by name and returns a new instance.
func GetPlugin(name string) (Plugin, error) {
	pluginRegistryMu.RLock()
	factory, exists := pluginRegistry[name]
	pluginRegistryMu.RUnlock()

	if !exists {
		available := ListPlugins()
		return nil, fmt.Errorf("unknown service %q (available: %v)", name, available)
	}

	return factory(), nil
}

// ListPlugins returns a sorted list of all registered enum plugin names.
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
