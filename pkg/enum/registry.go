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

// resetPlugins clears all registered enum plugins (for testing).
func resetPlugins() {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	pluginRegistry = make(map[string]PluginFactory)
}
