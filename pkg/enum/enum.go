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

// pkg/enum/enum.go
package enum

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Config defines the configuration for account enumeration.
type Config struct {
	Emails    []string      // emails to enumerate
	Services  []string      // service names to check (empty = all registered)
	Threads   int           // concurrent workers (default: 10)
	Timeout   time.Duration // per-check timeout (default: 10s)
	RateLimit float64       // max requests per second (0 = unlimited)
	Jitter    time.Duration // random delay variance for rate limiting
	Verbose   bool          // verbose logging to stderr
	ProxyURL  string        // proxy URL for HTTP enum sources (empty = direct)
}

// httpClientCtxKey is the context key under which the shared per-run enum HTTP
// client is stored. Plugin oracles retrieve it via HTTPClientFromContext so a
// single pooled (and possibly proxied) client is reused across all checks.
type httpClientCtxKey struct{}

// WithHTTPClient returns a context carrying client for plugin oracles to reuse.
func WithHTTPClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, httpClientCtxKey{}, client)
}

// HTTPClientFromContext returns the shared enum HTTP client stored in ctx, or
// nil if none was set.
func HTTPClientFromContext(ctx context.Context) *http.Client {
	client, _ := ctx.Value(httpClientCtxKey{}).(*http.Client)
	return client
}

// proxyURLCtxKey is the context key under which the per-run proxy URL is stored.
// Plugin oracles that build a specialized client (e.g. the google enumerator)
// read it via ProxyURLFromContext to honor --proxy.
type proxyURLCtxKey struct{}

// WithProxyURL returns a context carrying the proxy URL for plugin oracles that
// construct their own HTTP client.
func WithProxyURL(ctx context.Context, proxyURL string) context.Context {
	return context.WithValue(ctx, proxyURLCtxKey{}, proxyURL)
}

// ProxyURLFromContext returns the proxy URL stored in ctx, or "" if none was set.
func ProxyURLFromContext(ctx context.Context) string {
	proxyURL, _ := ctx.Value(proxyURLCtxKey{}).(string)
	return proxyURL
}

// validate checks the configuration and applies defaults.
func (c *Config) validate() error {
	if len(c.Emails) == 0 {
		return errors.New("emails required")
	}
	if c.Threads < 0 {
		return errors.New("threads must not be negative")
	}
	if c.RateLimit < 0 {
		return errors.New("rate limit must not be negative")
	}

	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Threads == 0 {
		c.Threads = 10
	}

	return nil
}

// EnumerateWithContext runs account enumeration with context support.
func EnumerateWithContext(ctx context.Context, cfg *Config) ([]Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return runWorkers(ctx, cfg)
}

// Enumerate runs account enumeration using context.Background().
func Enumerate(cfg *Config) ([]Result, error) {
	return EnumerateWithContext(context.Background(), cfg)
}
