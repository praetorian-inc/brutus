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

// Package brutus provides a modern Go library for credential brute-forcing
// with zero dependencies and library-first design.
//
// Quick Start:
//
//	config := &brutus.Config{
//	    Target:    "10.0.0.50:22",
//	    Protocol:  "ssh",
//	    Usernames: []string{"root", "admin"},
//	    Passwords: []string{"password", "admin"},
//	    Timeout:   5 * time.Second,
//	    Threads:   10,
//	}
//
//	results, err := brutus.Brute(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, r := range results {
//	    if r.Success {
//	        fmt.Printf("Valid: %s:%s\n", r.Username, r.Password)
//	    }
//	}
//
// Error Handling:
//
// Results distinguish between authentication failures (invalid credentials)
// and connection errors. Authentication failures have Success=false and Error=nil.
// Connection errors have Success=false and Error!=nil.
//
// Supported Protocols:
//
// - ssh: SSH password authentication
package brutus

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/brutus/pkg/badkeys"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

const (
	// MaxBannerLength limits banner size to prevent prompt injection
	MaxBannerLength = 500
	// MaxPasswordLength limits suggested password length
	MaxPasswordLength = 32
)

// =============================================================================
// Context Keys for TLS Mode
// =============================================================================

type contextKey string

const tlsModeContextKey contextKey = "tlsMode"

// ContextWithTLSMode adds TLSMode to the context
func ContextWithTLSMode(ctx context.Context, tlsMode string) context.Context {
	return context.WithValue(ctx, tlsModeContextKey, tlsMode)
}

// TLSModeFromContext retrieves TLSMode from the context (default: "disable")
func TLSModeFromContext(ctx context.Context) string {
	if mode, ok := ctx.Value(tlsModeContextKey).(string); ok {
		return mode
	}
	return "disable"
}

// Credential represents a pre-paired username with password or key.
// Use this instead of separate Usernames/Passwords/Keys arrays when you have
// specific credential pairs (e.g., badkeys where each key has an associated username).
type Credential struct {
	Username string // username to test
	Password string // password to test (empty for key-based auth)
	Key      []byte // SSH private key (nil for password-based auth)
}

// Config defines the configuration for a brute force attack.
type Config struct {
	Target        string        // host:port (e.g., "10.0.0.50:22")
	Protocol      string        // plugin name (e.g., "ssh")
	Usernames     []string      // usernames to test (Cartesian product with Passwords/Keys)
	Passwords     []string      // passwords to test (Cartesian product with Usernames)
	Keys          [][]byte      // SSH private keys to test (Cartesian product with Usernames)
	Credentials   []Credential  // pre-paired credentials (no Cartesian product)
	UseDefaults   bool          // load protocol-specific default credentials from embedded wordlists
	NoBadkeys     bool          // skip embedded bad SSH keys when UseDefaults is true
	Timeout       time.Duration // per-credential timeout (default: 10s)
	Threads       int           // concurrent workers (default: 10)
	StopOnSuccess bool          // stop after first valid cred (default: true)
	LLMConfig     *LLMConfig    // optional LLM-based banner analysis (nil = disabled)
	Plugin        Plugin        // optional: pre-configured plugin instance (bypasses GetPlugin)
	TLSMode       string        // TLS/SSL verification mode: "disable", "verify", "skip-verify" (default: "disable")
	RateLimit     float64       // max requests per second (0 = unlimited, default: 0)
	Jitter        time.Duration // random delay variance added to rate limiting (default: 0)
	MaxAttempts   int           // max password attempts per username (0 = unlimited)
	SprayMode     bool          // password spraying: loop users first, then passwords
}

// Result contains the outcome of testing a single credential.
type Result struct {
	Protocol string        // protocol used
	Target   string        // target tested
	Username string        // username tested
	Password string        // password tested
	Key      []byte        // SSH key (Phase 1B, nil in 1A)
	Success  bool          // authentication succeeded?
	Error    error         // connection/network error (nil for auth failure)
	Duration time.Duration // test duration

	// Banner and LLM suggestion tracking
	Banner            string   // service banner (if captured)
	LLMSuggested      bool     // was this credential suggested by LLM?
	LLMSuggestedCreds []string // all LLM suggestions for this service
}

// LLMConfig enables optional LLM-based banner analysis
type LLMConfig struct {
	Enabled  bool
	Provider string // "claude" (additional providers can be added via the plugin architecture)
	APIKey   string
	Model    string // Optional: model override
}

// BannerAnalyzer is an optional interface for intelligent credential suggestion
type BannerAnalyzer interface {
	Analyze(ctx context.Context, banner BannerInfo) ([]string, error)
}

// CredentialAnalyzer extends BannerAnalyzer to return full credential pairs
// Analyzers that implement this interface can return both username and password
type CredentialAnalyzer interface {
	BannerAnalyzer
	AnalyzeCredentials(ctx context.Context, banner BannerInfo) ([]Credential, error)
}

// BannerInfo contains service banner information
type BannerInfo struct {
	Protocol string
	Target   string
	Banner   string      // Raw banner text
	Headers  http.Header // For HTTP services (optional)
}

// AnalyzerFactory creates a new analyzer instance from configuration
type AnalyzerFactory func(cfg *LLMConfig) BannerAnalyzer

// Plugin defines the interface for authentication protocol implementations.
// Each plugin must implement credential testing for a specific protocol (SSH, FTP, etc.).
//
// Optional Key-Based Authentication:
// Plugins may optionally implement a TestKey method for key-based authentication:
//
//	type KeyPlugin interface {
//	    Plugin
//	    TestKey(ctx context.Context, target, username string, key []byte, timeout time.Duration) *Result
//	}
//
// If a plugin implements TestKey, the worker pool will automatically use it when
// Config.Keys is provided.
type Plugin interface {
	// Name returns the protocol name (e.g., "ssh", "ftp").
	Name() string

	// Test attempts to authenticate using the provided credentials.
	// Returns a Result indicating success or failure.
	//
	// For authentication failures (invalid credentials), Result.Success=false and Result.Error=nil.
	// For connection/network errors, Result.Success=false and Result.Error!=nil.
	//
	// The context can be used to cancel the operation early.
	// The timeout specifies the maximum duration for the authentication attempt.
	Test(ctx context.Context, target, username, password string, timeout time.Duration) *Result
}

// PluginFactory is a function that creates a new Plugin instance.
// Using a factory pattern ensures each call to Get returns a fresh instance,
// which is important for concurrent usage.
type PluginFactory func() Plugin

// =============================================================================
// Plugin Registry
// =============================================================================

var (
	pluginRegistryMu sync.RWMutex
	pluginRegistry   = make(map[string]PluginFactory)
)

// Register adds a plugin factory to the registry.
// This function should be called from plugin init() functions.
// Panics if a plugin with the same name is already registered.
func Register(name string, factory PluginFactory) {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	if _, exists := pluginRegistry[name]; exists {
		panic(fmt.Sprintf("brutus: plugin %q already registered", name))
	}

	pluginRegistry[name] = factory
}

// GetPlugin retrieves a plugin by name and returns a new instance.
// Returns an error if the plugin is not found.
// Each call returns a fresh instance from the factory.
func GetPlugin(name string) (Plugin, error) {
	pluginRegistryMu.RLock()
	factory, exists := pluginRegistry[name]
	pluginRegistryMu.RUnlock()

	if !exists {
		available := ListPlugins()
		return nil, fmt.Errorf("unknown protocol %q (available: %v)", name, available)
	}

	return factory(), nil
}

// ListPlugins returns a sorted list of all registered plugin names.
// The list is sorted to ensure deterministic output in error messages.
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

// ResetPlugins clears all registered plugins.
// This function is intended for testing only.
func ResetPlugins() {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	pluginRegistry = make(map[string]PluginFactory)
}

// =============================================================================
// Analyzer Registry
// =============================================================================

var (
	analyzerRegistryMu sync.RWMutex
	analyzerRegistry   = make(map[string]AnalyzerFactory)
)

// RegisterAnalyzer registers an analyzer factory for a provider name.
// This is called by analyzer implementations in their init() functions.
func RegisterAnalyzer(provider string, factory AnalyzerFactory) {
	analyzerRegistryMu.Lock()
	defer analyzerRegistryMu.Unlock()
	analyzerRegistry[provider] = factory
}

// GetAnalyzerFactory retrieves the factory for a given provider
func GetAnalyzerFactory(provider string) AnalyzerFactory {
	analyzerRegistryMu.RLock()
	defer analyzerRegistryMu.RUnlock()
	return analyzerRegistry[provider]
}

// =============================================================================
// Standard Banners
// =============================================================================

// standardBanners contains known standard banner patterns for each protocol
var standardBanners = map[string][]string{
	"ssh": {
		"SSH-2.0-OpenSSH",
		"SSH-2.0-libssh",
		"SSH-2.0-dropbear",
	},
	"telnet": {
		"Ubuntu",
		"Debian",
		"Linux",
		"FreeBSD",
	},
	"ftp": {
		"220 ProFTPD",
		"220 (vsFTPd",
		"220-FileZilla",
		"220 Pure-FTPd",
	},
	"mysql": {
		"MySQL 5.",
		"MySQL 8.",
		"MariaDB 10.",
		"Percona Server",
	},
	"snmp": {
		"Linux",
		"Cisco IOS",
		"Windows",
		"FreeBSD",
		"net-snmp",
		"HP ETHERNET",
		"APC",
		"Ubiquiti",
	},
}

// IsStandardBanner checks if a banner matches known standard patterns for the protocol.
// Returns true if the banner is standard (common/default), false if custom/modified.
//
// HTTP protocols (http, https, couchdb, elasticsearch, influxdb) always return false
// to enable LLM analysis, as they have application-specific banners (Grafana, Jenkins,
// Tomcat) that benefit from LLM credential suggestion.
//
// Unknown non-HTTP protocols or empty banners are assumed standard.
func IsStandardBanner(protocol, banner string) bool {
	// Empty banner - assume standard
	if banner == "" {
		return true
	}

	// HTTP protocols always need LLM analysis (application-specific banners)
	if isHTTPProtocol(protocol) {
		return false
	}

	// Get patterns for protocol
	patterns, ok := standardBanners[protocol]
	if !ok {
		// Unknown protocol - assume standard
		return true
	}

	// Check if banner matches any standard pattern
	for _, pattern := range patterns {
		if strings.Contains(banner, pattern) {
			return true
		}
	}

	// No match - custom banner
	return false
}

// =============================================================================
// Configuration Validation
// =============================================================================

// applyDefaults populates protocol-specific default credentials from embedded
// wordlists when UseDefaults is true and no credentials have been provided.
// Existing credentials are never overwritten.
func (c *Config) applyDefaults() {
	if !c.UseDefaults {
		return
	}

	hasCreds := len(c.Credentials) > 0
	hasPasswords := len(c.Passwords) > 0
	hasKeys := len(c.Keys) > 0

	// Load SSH badkeys as paired credentials when no keys/creds were provided
	if c.Protocol == "ssh" && !c.NoBadkeys && !hasCreds && !hasKeys {
		for _, k := range badkeys.GetSSHCredentials() {
			c.Credentials = append(c.Credentials, Credential{Username: k.Username, Key: k.Key})
		}
	}

	// Load wordlist defaults when no user-supplied credentials were provided
	if !hasCreds && !hasPasswords && !hasKeys {
		if defaults := DefaultCredentials(c.Protocol); len(defaults) > 0 {
			c.Credentials = append(c.Credentials, defaults...)
		}
	}
}

// validate checks the configuration and applies defaults.
func (c *Config) validate() error {
	if c.Target == "" {
		return errors.New("target is required")
	}
	if c.Protocol == "" {
		return errors.New("protocol is required")
	}

	c.applyDefaults()

	// Need either: paired Credentials OR (Usernames + Passwords/Keys)
	hasPairedCreds := len(c.Credentials) > 0
	hasUnpairedCreds := len(c.Usernames) > 0 && (len(c.Passwords) > 0 || len(c.Keys) > 0)
	if !hasPairedCreds && !hasUnpairedCreds {
		return errors.New("credentials required: use Credentials for paired, or Usernames with Passwords/Keys")
	}

	// Apply defaults
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Threads == 0 {
		c.Threads = 10
	}

	return nil
}

// =============================================================================
// Brute Force Execution
// =============================================================================

// Brute executes a brute force attack using the provided configuration.
func Brute(cfg *Config) ([]Result, error) {
	// 1. Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// 2. Get protocol plugin (use provided plugin if set, otherwise lookup by name)
	var plug Plugin
	if cfg.Plugin != nil {
		plug = cfg.Plugin
	} else {
		var err error
		plug, err = GetPlugin(cfg.Protocol)
		if err != nil {
			return nil, err
		}
	}

	// 3. Run worker pool
	ctx := context.Background()
	results, err := runWorkers(ctx, cfg, plug)
	if err != nil {
		return results, fmt.Errorf("brute force failed: %w", err)
	}

	return results, nil
}

// =============================================================================
// Worker Pool Implementation
// =============================================================================

// credential represents a username/password or username/key combination to test.
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

// runWorkers executes credential testing using a bounded worker pool.
func runWorkers(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
	// Add TLSMode to context at the start
	ctx = ContextWithTLSMode(ctx, cfg.TLSMode)

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

// isHTTPProtocol returns true if the protocol uses HTTP Basic Auth
// and can benefit from LLM-based application detection.
func isHTTPProtocol(protocol string) bool {
	switch protocol {
	case "http", "https", "couchdb", "elasticsearch", "influxdb":
		return true
	default:
		return false
	}
}

// runWorkersDefault executes credential testing using a bounded worker pool.
// Uses errgroup for concurrency control and context cancellation for early stopping.
func runWorkersDefault(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
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

	// Result collection with mutex protection
	var (
		results       []Result
		attemptCounts = make(map[string]int)
		attemptMu     sync.Mutex
		mu            sync.Mutex
		found         atomic.Bool
	)

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

	// Reorder for spray mode if enabled
	if cfg.SprayMode {
		credentials = reorderForSpray(credentials)
	}

	// Launch workers
	for _, cred := range credentials {
		// Check early stop before launching new worker
		if cfg.StopOnSuccess && found.Load() {
			break
		}

		// Capture loop variable for closure
		cred := cred

		g.Go(func() error {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil
			default:
			}

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

			// Test credential (key-based or password-based)
			var result *Result
			if cred.key != nil {
				// Key-based authentication
				// Check if plugin supports key auth
				type keyPlugin interface {
					TestKey(ctx context.Context, target, username string, key []byte, timeout time.Duration) *Result
				}
				if kp, ok := plug.(keyPlugin); ok {
					result = kp.TestKey(ctx, cfg.Target, cred.username, cred.key, cfg.Timeout)
				} else {
					// Plugin doesn't support key auth, skip
					return nil
				}
			} else {
				// Password-based authentication
				result = plug.Test(ctx, cfg.Target, cred.username, cred.password, cfg.Timeout)
			}

			// Collect result
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()

			// Handle success with early stop
			if result.Success && cfg.StopOnSuccess {
				found.Store(true)
				cancel() // Signal all workers to stop
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

// runWorkersWithLLM executes credential testing with optional LLM-based banner analysis.
// Phase 1: Capture banner with dummy credential
// Phase 2: Check if standard banner (skip LLM if standard)
// Phase 3: Analyze non-standard banner with LLM
// Phase 4: Test LLM suggestions first (priority)
// Phase 5: Test default credentials
// Phase 6: Run workers with combined credential list
func runWorkersWithLLM(ctx context.Context, cfg *Config, plug Plugin) ([]Result, error) {
	// Phase 1: Capture banner with dummy credential
	banner := captureBanner(ctx, cfg, plug)

	// Phase 2: Check if standard banner
	if IsStandardBanner(cfg.Protocol, banner.Banner) {
		// Standard banner - use default credentials only
		return runWorkersDefault(ctx, cfg, plug)
	}

	// Phase 3: Non-standard banner - get LLM suggestions
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
	return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)
}

// captureBanner makes an initial connection to capture the service banner.
// Uses a dummy credential to trigger the connection and extract banner information.
func captureBanner(ctx context.Context, cfg *Config, plug Plugin) BannerInfo {
	// Use first username with empty password for banner capture
	username := cfg.Usernames[0]

	// Test with dummy credential just to capture banner
	result := plug.Test(ctx, cfg.Target, username, "", cfg.Timeout)

	return BannerInfo{
		Protocol: cfg.Protocol,
		Target:   cfg.Target,
		Banner:   result.Banner,
	}
}

// createAnalyzer creates the appropriate LLM analyzer based on provider configuration.
// Returns nil if provider is unknown or configuration is invalid.
// Analyzers must register themselves using RegisterAnalyzer() in their init() functions.
func createAnalyzer(cfg *LLMConfig) BannerAnalyzer {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	// Get analyzer from registry
	factory := GetAnalyzerFactory(cfg.Provider)
	if factory == nil {
		return nil
	}

	return factory(cfg)
}

// runWorkersWithCredentials executes credential testing with a pre-built credential list.
// Similar to runWorkersDefault but accepts a pre-built credential list with LLM tracking.
func runWorkersWithCredentials(ctx context.Context, cfg *Config, plug Plugin, credentials []credential, llmSuggestions []string) ([]Result, error) {
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

	// Result collection with mutex protection
	var (
		results       []Result
		attemptCounts = make(map[string]int)
		attemptMu     sync.Mutex
		mu            sync.Mutex
		found         atomic.Bool
	)

	// Launch workers
	for _, cred := range credentials {
		// Check early stop before launching new worker
		if cfg.StopOnSuccess && found.Load() {
			break
		}

		// Capture loop variable for closure
		cred := cred

		g.Go(func() error {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil
			default:
			}

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

			// Test credential
			result := plug.Test(ctx, cfg.Target, cred.username, cred.password, cfg.Timeout)

			// Populate LLM tracking fields
			result.LLMSuggested = cred.llmSuggested
			result.LLMSuggestedCreds = llmSuggestions

			// Collect result
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()

			// Handle success with early stop
			if result.Success && cfg.StopOnSuccess {
				found.Store(true)
				cancel() // Signal all workers to stop
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

// =============================================================================
// LLM Utilities
// =============================================================================

// BuildPrompt constructs the LLM prompt for banner analysis
func BuildPrompt(protocol, banner string) string {
	return `You are analyzing a service banner for penetration testing.

Protocol: ` + protocol + `
Banner (sanitized):
"""
` + banner + `
"""

Task: Suggest 3-4 likely default passwords for this specific service based on:
1. Vendor/product name in banner
2. Version numbers
3. Common defaults for this product

Return ONLY a JSON array of passwords, nothing else:
["password1", "password2", "password3"]

Rules:
- Passwords must be realistic defaults (not random)
- Max 32 characters each
- Alphanumeric + common symbols only
- NO commentary, NO explanations
`
}

// SanitizeBanner removes control chars and limits length to prevent prompt injection
func SanitizeBanner(banner string) string {
	// 1. Remove null bytes
	cleaned := strings.ReplaceAll(banner, "\x00", "")

	// 2. Remove ANSI escape codes
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	cleaned = ansiRegex.ReplaceAllString(cleaned, "")

	// 3. Remove triple quotes (prevent prompt escape)
	cleaned = strings.ReplaceAll(cleaned, `"""`, "")

	// 4. Limit length
	if len(cleaned) > MaxBannerLength {
		cleaned = cleaned[:MaxBannerLength]
	}

	return cleaned
}

// ValidateSuggestions ensures LLM output is safe
func ValidateSuggestions(passwords []string) []string {
	valid := []string{}

	for _, pwd := range passwords {
		// 1. Length check
		if pwd == "" || len(pwd) > MaxPasswordLength {
			continue
		}

		// 2. Character whitelist (alphanumeric + common symbols)
		if !IsValidPassword(pwd) {
			continue
		}

		valid = append(valid, pwd)
		if len(valid) >= 4 {
			break // Max 4 suggestions
		}
	}

	return valid
}

// IsValidPassword checks for safe characters
func IsValidPassword(pwd string) bool {
	// Allow: a-zA-Z0-9 and common symbols: !@#$%^&*()-_=+[]{}
	allowedPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}]+$`)
	return allowedPattern.MatchString(pwd)
}
