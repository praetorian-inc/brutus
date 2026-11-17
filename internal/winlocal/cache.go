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

package winlocal

import (
	"context"
	"sync"
)

type cached struct {
	name string
	err  error
}

type flight struct {
	done chan struct{}
	name string
	err  error
}

var (
	cacheMu  sync.Mutex
	cache    = map[string]cached{}
	inflight = map[string]*flight{}
)

// Resolve returns the computer name for key, probing at most once per process.
//
// A failed probe is cached. Retrying it on every credential would not make the
// name appear, and falling back to an empty domain would turn the spray into
// domain authentication. Cancellation is not cached.
func Resolve(ctx context.Context, key string, probe func(context.Context) (string, error)) (string, error) {
	cacheMu.Lock()
	if e, ok := cache[key]; ok {
		cacheMu.Unlock()
		return e.name, e.err
	}
	if f, ok := inflight[key]; ok {
		cacheMu.Unlock()
		select {
		case <-f.done:
			return f.name, f.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	inflight[key] = f
	cacheMu.Unlock()

	name, err := probe(ctx)
	store := ctx.Err() == nil
	if !store {
		err = ctx.Err()
		name = ""
	}

	f.name, f.err = name, err
	close(f.done)

	cacheMu.Lock()
	delete(inflight, key)
	if store {
		cache[key] = cached{name: name, err: err}
	}
	cacheMu.Unlock()
	return name, err
}
