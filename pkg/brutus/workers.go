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

package brutus

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

// credential represents a single authentication attempt.
type credential struct {
	username     string
	password     string
	key          []byte // SSH private key (optional, for key-based auth)
	llmSuggested bool   // True if this credential was suggested by LLM
}

// generateCredentials creates all possible username/password combinations.
func generateCredentials(usernames, passwords []string) []credential {
	creds := make([]credential, 0, len(usernames)*len(passwords))

	for _, username := range usernames {
		for _, password := range passwords {
			creds = append(creds, credential{
				username: username,
				password: password,
			})
		}
	}

	return creds
}

// generateKeyCredentials creates all possible username/key combinations.
func generateKeyCredentials(usernames []string, keys [][]byte) []credential {
	creds := make([]credential, 0, len(usernames)*len(keys))

	for _, username := range usernames {
		for _, key := range keys {
			creds = append(creds, credential{
				username: username,
				key:      key,
			})
		}
	}

	return creds
}

// reorderForSpray reorders credentials to try each password across all users
// before moving to the next password (password spraying mode).
func reorderForSpray(creds []credential) []credential {
	if len(creds) == 0 {
		return creds
	}

	// Group credentials by password
	byPassword := make(map[string][]credential)
	passwordOrder := []string{}

	for _, c := range creds {
		if _, seen := byPassword[c.password]; !seen {
			passwordOrder = append(passwordOrder, c.password)
		}
		byPassword[c.password] = append(byPassword[c.password], c)
	}

	// Rebuild credentials list: all users for password1, then all users for password2, etc.
	result := make([]credential, 0, len(creds))
	for _, pass := range passwordOrder {
		result = append(result, byPassword[pass]...)
	}

	return result
}

// pluginConfigFromConfig builds a PluginConfig from the top-level Config.
// This replaces the former pattern of copying config into context values.
func pluginConfigFromConfig(cfg *Config) PluginConfig {
	return PluginConfig{
		TLSMode:      cfg.TLSMode,
		NoVision:     !cfg.AIMode,
		NoStickyKeys: !cfg.StickyKeys,
		ProxyURL:     cfg.ProxyURL,
	}
}

// runWorkers executes credential testing using a bounded worker pool.
func runWorkers(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
	// Pre-check: unauthenticated access detection (runs once per target).
	// Skip when Nerva has already detected anonymous access (SkipUnauthCheck).
	if !cfg.SkipUnauthCheck {
		if checker, ok := plug.(UnauthChecker); ok {
			if r := checker.CheckUnauth(ctx, cfg.Target, cfg.Timeout, pluginConfigFromConfig(cfg)); r != nil && r.Success {
				// Service doesn't enforce authentication — credential testing
				// would produce misleading results (every password "works").
				// Return only the unauthenticated access finding.
				return []Result{*r}, nil
			}
		}
	}

	// Check if LLM analysis is enabled AND protocol supports it
	// LLM banner analysis only makes sense for HTTP Basic Auth where we can
	// detect the application from the response headers/body
	if cfg.LLMConfig != nil && cfg.LLMConfig.Enabled && isHTTPProtocol(cfg.Protocol) {
		// Use LLM-enhanced flow: capture banner, analyze, test suggestions
		return runWorkersWithLLM(ctx, cfg, plug)
	}
	// Default flow: test credentials without LLM analysis
	return runWorkersDefault(ctx, cfg, plug)
}

// executeWorkerPool is the shared worker pool implementation used by both
// runWorkersDefault and runWorkersWithLLM. It handles concurrency control,
// rate limiting, jitter, max attempts, retry with backoff, adaptive pacing,
// result collection, and early stopping.
func executeWorkerPool(ctx context.Context, cfg *Config, plug Plugin, credentials []credential, llmSuggestions []string) ([]Result, error) {
	// Build plugin config once for all workers
	pluginCfg := pluginConfigFromConfig(cfg)

	// Create cancellable context for early stop
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup errgroup with bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.Threads)

	// Create rate limiter if configured
	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}

	// Create backoff controller for retry and adaptive pacing
	var bc *backoffController
	if cfg.MaxRetries > 0 {
		bc = newBackoffController(500*time.Millisecond, 30*time.Second, cfg.Verbose)
	}

	// Result collection with mutex protection
	var (
		results       []Result
		attemptCounts = make(map[string]int)
		attemptMu     sync.Mutex
		mu            sync.Mutex
		crackedUsers  = make(map[string]bool) // per-user early stop
	)

	// Launch workers
	for _, cred := range credentials {

		// Capture loop variable for closure
		cred := cred

		g.Go(func() error {
			// Recover from plugin panics to prevent crashing the entire scan
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "brutus: panic in worker for %s@%s: %v\n%s\n",
						cred.username, cfg.Target, r, debug.Stack())
					// Use TryLock to avoid deadlock if panic occurred while mu was held
					if mu.TryLock() {
						results = append(results, Result{
							Protocol: cfg.Protocol,
							Target:   cfg.Target,
							Username: cred.username,
							Password: cred.password,
							Success:  false,
							Error:    fmt.Errorf("plugin panic: %v", r),
						})
						mu.Unlock()
					}
				}
			}()

			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Skip if this user already has a valid credential
			attemptMu.Lock()
			if crackedUsers[cred.username] {
				attemptMu.Unlock()
				return nil
			}
			attemptMu.Unlock()

			// Apply rate limiting if configured
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					return nil // Context canceled
				}
				// Apply jitter if configured
				if cfg.Jitter > 0 {
					jitterDuration := time.Duration(rand.Int63n(int64(cfg.Jitter)))
					select {
					case <-time.After(jitterDuration):
						// Jitter sleep completed
					case <-ctx.Done():
						return nil // Context canceled during jitter
					}
				}
			}

			// Check max attempts per user
			if cfg.MaxAttempts > 0 {
				attemptMu.Lock()
				if attemptCounts[cred.username] >= cfg.MaxAttempts {
					attemptMu.Unlock()
					return nil
				}
				attemptCounts[cred.username]++
				attemptMu.Unlock()
			}

			// Re-check context before expensive network call
			// (cancel may have fired during rate limiting or jitter)
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Apply adaptive pacing if backoff controller is active
			if bc != nil {
				if delay := bc.adaptiveDelay(); delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return nil
					}
				}
			}

			// Test credential with retry on connection errors
			var result *Result
			maxAttempts := 1
			if bc != nil {
				maxAttempts = cfg.MaxRetries + 1
			}

			for attempt := 0; attempt < maxAttempts; attempt++ {
				// Retry backoff (skip for first attempt)
				if attempt > 0 {
					delay := bc.retryDelay(attempt - 1)
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return nil
					}
				}

				if cred.key != nil {
					// Key-based authentication
					if kp, ok := plug.(KeyPlugin); ok {
						result = kp.TestKey(ctx, cfg.Target, cred.username, cred.key, cfg.Timeout, pluginCfg)
					} else {
						// Plugin doesn't support key auth, skip
						return nil
					}
				} else {
					// Password-based authentication
					result = plug.Test(ctx, cfg.Target, cred.username, cred.password, cfg.Timeout, pluginCfg)
				}

				// If no connection error, stop retrying
				if result.Error == nil {
					break
				}

				// Connection error on last attempt - keep the error result
				if attempt == maxAttempts-1 {
					break
				}
			}

			// Update adaptive controller
			if bc != nil {
				if result.Error != nil {
					bc.recordError()
				} else {
					bc.recordSuccess()
				}
			}

			// Populate LLM tracking fields if suggestions were provided
			if len(llmSuggestions) > 0 {
				result.LLMSuggested = cred.llmSuggested
				result.LLMSuggestedCreds = llmSuggestions
			}

			// Collect result
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()

			// Mark user as cracked to skip remaining passwords for this user
			if result.Success {
				attemptMu.Lock()
				crackedUsers[cred.username] = true
				attemptMu.Unlock()
			}

			return nil
		})
	}

	// Wait for all workers to complete
	if err := g.Wait(); err != nil && err != context.Canceled {
		return results, err
	}

	return results, nil
}

// runWorkersDefault executes credential testing using a bounded worker pool.
// Uses errgroup for concurrency control and context cancellation for early stopping.
func runWorkersDefault(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
	// Generate all credential combinations
	var credentials []credential

	// Add pre-paired credentials (no Cartesian product)
	for _, c := range cfg.Credentials {
		credentials = append(credentials, credential{
			username: c.Username,
			password: c.Password,
			key:      c.Key,
		})
	}

	// Add password-based credentials (Cartesian product)
	if len(cfg.Passwords) > 0 {
		credentials = append(credentials, generateCredentials(cfg.Usernames, cfg.Passwords)...)
	}

	// Add key-based credentials (Cartesian product, if supported by plugin)
	if len(cfg.Keys) > 0 {
		credentials = append(credentials, generateKeyCredentials(cfg.Usernames, cfg.Keys)...)
	}

	// Reorder credentials for spray ordering: try each password across all users
	// before moving to the next password. This avoids account lockout.
	credentials = reorderForSpray(credentials)

	// Execute worker pool with no LLM suggestions
	return executeWorkerPool(ctx, cfg, plug, credentials, nil)
}

// runWorkersWithLLM executes credential testing with LLM-based banner analysis
// for HTTP protocols. Captures the banner, analyzes it with the LLM to suggest
// application-specific credentials, then tests those before falling back to defaults.
//
// This function is only called for HTTP protocols (http, https, couchdb,
// elasticsearch, influxdb) where banner analysis can identify the application
// (e.g., Grafana, Jenkins, Tomcat) and suggest relevant default credentials.
func runWorkersWithLLM(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
	// Capture banner from HTTP response
	banner := captureBanner(ctx, cfg, plug)

	// Analyze banner with LLM to get application-specific credential suggestions
	analyzer := createAnalyzer(cfg.LLMConfig)
	if analyzer == nil {
		// Analyzer creation failed - fallback to defaults
		return runWorkersDefault(ctx, cfg, plug)
	}

	suggestions, err := analyzer.Analyze(ctx, banner)
	if err != nil {
		// LLM analysis failed - fallback to defaults
		return runWorkersDefault(ctx, cfg, plug)
	}

	// Phase 4: Build LLM credential list (test these first)
	llmCreds := []credential{}
	for _, username := range cfg.Usernames {
		for _, password := range suggestions {
			llmCreds = append(llmCreds, credential{
				username:     username,
				password:     password,
				llmSuggested: true,
			})
		}
	}

	// Phase 5: Build default credential list
	defaultCreds := generateCredentials(cfg.Usernames, cfg.Passwords)

	// Phase 6: Combine LLM suggestions first, then defaults
	allCreds := make([]credential, 0, len(llmCreds)+len(defaultCreds))
	allCreds = append(allCreds, llmCreds...)
	allCreds = append(allCreds, defaultCreds...)

	// Run workers with combined credentials
	return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
}

// captureBanner makes an initial connection to capture the service banner.
// Uses a dummy credential to trigger the connection and extract banner information.
func captureBanner(ctx context.Context, cfg *Config, plug Plugin) BannerInfo {
	// Use first username with empty password for banner capture
	// If no usernames provided (only pre-paired Credentials), extract from first Credential
	var username string
	if len(cfg.Usernames) > 0 {
		username = cfg.Usernames[0]
	} else if len(cfg.Credentials) > 0 {
		username = cfg.Credentials[0].Username
	}
	// Empty username is acceptable for banner capture (some protocols don't need it)

	// Test with dummy credential just to capture banner
	result := plug.Test(ctx, cfg.Target, username, "", cfg.Timeout, pluginConfigFromConfig(cfg))

	return BannerInfo{
		Protocol: cfg.Protocol,
		Target:   cfg.Target,
		Banner:   result.Banner,
	}
}
