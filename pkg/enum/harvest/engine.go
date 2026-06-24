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

// pkg/enum/harvest/engine.go
package harvest

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

const defaultThreads = 10

// Options configures a harvest run.
type Options struct {
	Domain    string
	Sources   []string      // empty = all registered
	Threads   int           // <= 0 defaults to 10
	Timeout   time.Duration // per-source HTTP budget
	RateLimit float64       // req/s across the run (0 = unlimited)
	Jitter    time.Duration
	Limit     int    // per-source cap on emails kept (0 = no cap)
	ProxyURL  string // "" = direct
	Verbose   bool
}

// Harvest fans out across the selected free sources, collecting and
// corroboration-scoring emails for opts.Domain. It validates the domain before
// any network use (security P0-1), routes all source HTTP through a proxy-aware
// client (security P0-2), and isolates per-source failures so one source erroring
// or panicking never fails the run. Returns a Report sorted by Count desc, Email asc.
func Harvest(ctx context.Context, opts Options) (*Report, error) {
	domain, err := validateDomain(opts.Domain)
	if err != nil {
		return nil, err
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = defaultThreads
	}

	names := opts.Sources
	if len(names) == 0 {
		names = ListSources()
	}

	client, err := enum.NewEnumHTTPClientWithProxy(opts.Timeout, opts.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("building harvest HTTP client: %w", err)
	}

	srcs := make([]Source, 0, len(names))
	for _, name := range names {
		src, err := GetSource(name, client)
		if err != nil {
			return nil, err // unknown source is a usage error — fail fast
		}
		srcs = append(srcs, src)
	}

	throttle := Throttle{Jitter: opts.Jitter}
	if opts.RateLimit > 0 {
		throttle.Limiter = rate.NewLimiter(rate.Limit(opts.RateLimit), 1)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(threads)

	var (
		agg = make(map[string]map[string]struct{}) // email -> set of source names
		mu  sync.Mutex
	)

	for _, src := range srcs {
		src := src
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "harvest: panic in source %s: %v\n%s\n",
							src.Name(), r, debug.Stack())
					}
				}
			}()

			if err := throttle.Wait(ctx); err != nil {
				return nil
			}

			raw, err := src.Search(ctx, domain)
			if err != nil {
				if opts.Verbose {
					// Log the source name only — NEVER the wrapped error, which
					// embeds the full request URL (and thus the domain in the
					// query string) via *url.Error (security P1-3; mirrors the
					// "full URL is never logged" rule in pkg/enum/hunter).
					fmt.Fprintf(os.Stderr, "harvest: source %s failed\n", src.Name())
				}
				return nil // per-source isolation: never fail the run
			}

			emails := collectEmails(raw, domain, opts.Limit)

			mu.Lock()
			for _, email := range emails {
				if agg[email] == nil {
					agg[email] = make(map[string]struct{})
				}
				agg[email][src.Name()] = struct{}{}
			}
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()

	return aggregateToReport(domain, agg), nil
}

// collectEmails normalizes/domain-anchors a source's raw emails through the
// shared extractor and applies the per-source limit (0 = no cap).
func collectEmails(raw []string, domain string, limit int) []string {
	emails := ExtractEmails(strings.Join(raw, "\n"), domain, true)
	if limit > 0 && len(emails) > limit {
		emails = emails[:limit]
	}
	return emails
}

// aggregateToReport converts the attribution map into a sorted Report.
func aggregateToReport(domain string, agg map[string]map[string]struct{}) *Report {
	hits := make([]EmailHit, 0, len(agg))
	for email, srcSet := range agg {
		sources := make([]string, 0, len(srcSet))
		for name := range srcSet {
			sources = append(sources, name)
		}
		sort.Strings(sources)
		hits = append(hits, EmailHit{Email: email, Sources: sources, Count: len(sources)})
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count != hits[j].Count {
			return hits[i].Count > hits[j].Count
		}
		return hits[i].Email < hits[j].Email
	})

	return &Report{Domain: domain, Hits: hits}
}
