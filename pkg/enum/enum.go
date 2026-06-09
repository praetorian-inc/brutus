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
