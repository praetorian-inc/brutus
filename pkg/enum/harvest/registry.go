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

// pkg/enum/harvest/registry.go
package harvest

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

var (
	sourceRegistryMu sync.RWMutex
	sourceRegistry   = make(map[string]SourceFactory)
)

// Register adds a harvest source factory to the registry.
// Called from source init() functions. Panics if duplicate.
func Register(name string, f SourceFactory) {
	sourceRegistryMu.Lock()
	defer sourceRegistryMu.Unlock()

	if _, exists := sourceRegistry[name]; exists {
		panic(fmt.Sprintf("harvest: source %q already registered", name))
	}

	sourceRegistry[name] = f
}

// GetSource retrieves a harvest source by name, building it with the given client.
func GetSource(name string, client *http.Client) (Source, error) {
	sourceRegistryMu.RLock()
	f, exists := sourceRegistry[name]
	sourceRegistryMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown source %q (available: %v)", name, ListSources())
	}

	return f(client), nil
}

// ListSources returns a sorted list of all registered harvest source names.
func ListSources() []string {
	sourceRegistryMu.RLock()
	defer sourceRegistryMu.RUnlock()

	names := make([]string, 0, len(sourceRegistry))
	for name := range sourceRegistry {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}
