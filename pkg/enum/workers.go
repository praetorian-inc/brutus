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

// pkg/enum/workers.go
package enum

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// enumTask represents a single enumeration check to perform.
//
// first/last carry the name the email was generated from (empty for supplied
// addresses) so runTasks can stamp it onto the resulting Result. They are
// never passed to the Plugin.
type enumTask struct {
	email   string
	first   string
	last    string
	service string
	plugin  Plugin
}

// runWorkers executes enumeration checks using a bounded worker pool.
// Iterates emails x services, applying rate limiting and jitter.
func runWorkers(ctx context.Context, cfg *Config) ([]Result, error) {
	// Resolve services to check
	services := cfg.Services
	if len(services) == 0 {
		services = ListPlugins()
	}

	// Build task list: targets x services
	var tasks []enumTask
	for _, target := range cfg.Targets {
		for _, svcName := range services {
			plug, err := GetPlugin(svcName)
			if err != nil {
				return nil, fmt.Errorf("resolving service %q: %w", svcName, err)
			}
			tasks = append(tasks, enumTask{
				email:   target.Email,
				first:   target.First,
				last:    target.Last,
				service: svcName,
				plugin:  plug,
			})
		}
	}

	return runTasks(ctx, cfg, tasks)
}

// runTasks executes a pre-built task list using a bounded worker pool,
// applying rate limiting, jitter, context cancellation, and per-goroutine panic
// recovery. It is the shared execution core for both the registry-keyed
// runWorkers and the registry-bypassing EnumerateWithPlugin.
func runTasks(ctx context.Context, cfg *Config, tasks []enumTask) ([]Result, error) {
	// Setup errgroup with bounded concurrency
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Build one shared enum HTTP client for the whole run so plugin oracles
	// reuse a single pooled (and possibly proxied) transport. Surfaces proxy
	// configuration errors once, before any checks run.
	httpClient, err := NewEnumHTTPClientWithProxy(cfg.Timeout, cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("configuring enum HTTP client: %w", err)
	}
	ctx = WithHTTPClient(ctx, httpClient)
	ctx = WithProxyURL(ctx, cfg.ProxyURL)

	g, ctx := errgroup.WithContext(ctx)
	// Normalize thread count: 0 would deadlock errgroup.SetLimit (no goroutine
	// can ever run) and a negative value means unbounded. Clamp to a safe
	// positive default of 1 (serial execution).
	threads := cfg.Threads
	if threads <= 0 {
		threads = 1
	}
	g.SetLimit(threads)

	// Rate limiter
	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}

	// Result collection
	var (
		results []Result
		mu      sync.Mutex
	)

	for _, task := range tasks {
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "enum: panic checking %s on %s: %v\n%s\n",
						task.email, task.service, r, debug.Stack())
					mu.Lock()
					results = append(results, Result{
						Service: task.service,
						Email:   task.email,
						First:   task.first,
						Last:    task.last,
						Error:   fmt.Errorf("plugin panicked: %v", r),
					})
					mu.Unlock()
				}
			}()

			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Rate limiting
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					return nil
				}
				if cfg.Jitter > 0 {
					jitter := time.Duration(rand.Int63n(int64(cfg.Jitter)))
					select {
					case <-time.After(jitter):
					case <-ctx.Done():
						return nil
					}
				}
			}

			// Execute check. The Plugin receives only the email — names are
			// stamped on afterwards, which is what keeps the Plugin interface
			// (and every per-service checker) unaware of them.
			result := task.plugin.Check(ctx, task.email, cfg.Timeout)
			if result == nil {
				result = &Result{
					Service: task.service,
					Email:   task.email,
					Error:   fmt.Errorf("plugin returned nil result"),
				}
			}

			// Stamp the generated name onto the result. A name is a property of
			// the address, not of the check outcome, so this applies on every
			// path: clean checks, plugin errors, and the nil-result substitute
			// above (the panic path stamps it in the deferred recover).
			result.First = task.first
			result.Last = task.last

			if cfg.Verbose && result.Error != nil {
				fmt.Fprintf(os.Stderr, "enum: error checking %s on %s: %v\n",
					task.email, task.service, result.Error)
			}

			mu.Lock()
			results = append(results, *result)
			mu.Unlock()

			return nil
		})
	}

	_ = g.Wait()

	return results, nil
}
