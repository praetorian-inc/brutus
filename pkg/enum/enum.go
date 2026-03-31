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
