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
type enumTask struct {
	email   string
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

	// Build task list: emails x services
	var tasks []enumTask
	for _, email := range cfg.Emails {
		for _, svcName := range services {
			plug, err := GetPlugin(svcName)
			if err != nil {
				return nil, fmt.Errorf("resolving service %q: %w", svcName, err)
			}
			tasks = append(tasks, enumTask{
				email:   email,
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
	g.SetLimit(cfg.Threads)

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

			// Execute check
			result := task.plugin.Check(ctx, task.email, cfg.Timeout)
			if result == nil {
				result = &Result{
					Service: task.service,
					Email:   task.email,
					Error:   fmt.Errorf("plugin returned nil result"),
				}
			}

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
