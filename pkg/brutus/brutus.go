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
// Context-Aware Usage:
//
// For cancellable operations, use BruteWithContext:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	results, err := brutus.BruteWithContext(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
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
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/badkeys"
)

// PluginConfig carries per-attempt configuration that plugins may need.
// It is built by the worker pool from Config and passed to Plugin.Test /
// KeyPlugin.TestKey, replacing the former pattern of smuggling values
// through context.WithValue.
type PluginConfig struct {
	TLSMode      string // "disable", "verify", "skip-verify" (default: "disable")
	NoVision     bool   // disable Vision API for screenshot analysis (RDP)
	NoStickyKeys bool   // disable sticky keys backdoor detection (RDP)
	ProxyURL     string // SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080")
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
	Target          string        // host:port (e.g., "10.0.0.50:22")
	Protocol        string        // plugin name (e.g., "ssh")
	Usernames       []string      // usernames to test (Cartesian product with Passwords/Keys)
	Passwords       []string      // passwords to test (Cartesian product with Usernames)
	Keys            [][]byte      // SSH private keys to test (Cartesian product with Usernames)
	Credentials     []Credential  // pre-paired credentials (no Cartesian product)
	UseDefaults     bool          // load protocol-specific default credentials from embedded wordlists
	NoBadkeys       bool          // skip embedded bad SSH keys when UseDefaults is true
	BadkeysOnly     bool          // only test embedded bad SSH keys (skip password wordlists)
	Timeout         time.Duration // per-credential timeout (default: 10s)
	Threads         int           // concurrent workers (default: 10)
	LLMConfig       *LLMConfig    // optional LLM-based banner analysis (nil = disabled)
	Plugin          Plugin        // optional: pre-configured plugin instance (bypasses GetPlugin)
	TLSMode         string        // TLS/SSL verification mode: "disable", "verify", "skip-verify" (default: "disable")
	RateLimit       float64       // max requests per second (0 = unlimited, default: 0)
	Jitter          time.Duration // random delay variance added to rate limiting (default: 0)
	MaxAttempts     int           // max password attempts per username (0 = unlimited)
	MaxRetries      int           // max retries per credential on connection error (0 = no retry, default: 0)
	Verbose         bool          // enable verbose logging to stderr (default: false)
	StickyKeys      bool          // enable sticky keys backdoor detection (RDP)
	AIMode          bool          // enable Vision API for screenshot analysis (RDP)
	SkipUnauthCheck bool          // skip CheckUnauth probe (when Nerva already detected it)
	Mode            Mode          // aggressiveness tier for wordlist depth (default: ModeDefault)
	ProxyURL        string        // SOCKS5 proxy URL for all connections (e.g., "socks5://127.0.0.1:1080")
}

// Result contains the outcome of testing a single credential.
type Result struct {
	Protocol      string        // protocol used
	Target        string        // target tested
	Username      string        // username tested
	Password      string        // password tested
	Key           []byte        // SSH key (Phase 1B, nil in 1A)
	Success       bool          // authentication succeeded?
	Indeterminate bool          // check could not produce a clean/dirty verdict; rerun
	Error         error         // connection/network error (nil for auth failure)
	Duration      time.Duration // test duration

	// Banner and LLM suggestion tracking
	Banner            string   // service banner (if captured)
	LLMSuggested      bool     // was this credential suggested by LLM?
	LLMSuggestedCreds []string // all LLM suggestions for this service

	// Scan metadata (optional, used in --scan mode for backdoor detection)
	ScanType string // scan type identifier (e.g., "sticky_keys", "utilman")
}

// NewResult creates a Result pre-filled with common fields and Success=false.
// This is a convenience constructor to eliminate boilerplate across plugins.
func NewResult(protocol, target, username, password string) *Result {
	return &Result{
		Protocol: protocol,
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}
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
// Thread Safety: Plugin instances may be shared across concurrent goroutines
// in the worker pool. Implementations MUST be safe for concurrent use.
// Stateless plugins (the common case) are inherently safe. If a plugin
// maintains mutable state, it must use its own synchronization (e.g., sync.Mutex).
//
// Optional Key-Based Authentication:
// Plugins may optionally implement the KeyPlugin interface for key-based authentication.
// If a plugin implements KeyPlugin, the worker pool will automatically use it when
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
	// The pluginCfg carries per-attempt configuration (TLS mode, feature flags).
	Test(ctx context.Context, target, username, password string, timeout time.Duration, pluginCfg PluginConfig) *Result
}

// KeyPlugin extends Plugin with key-based authentication support.
//
// Protocols that support public key authentication (e.g., SSH) can optionally implement
// this interface. The worker pool will automatically detect and use TestKey when
// Config.Keys is provided.
type KeyPlugin interface {
	Plugin

	// TestKey attempts authentication with username and SSH private key
	TestKey(ctx context.Context, target, username string, key []byte, timeout time.Duration, pluginCfg PluginConfig) *Result
}

// UnauthChecker is an optional interface for plugins that can detect
// unauthenticated access to a service. The worker pool calls CheckUnauth
// once per target before credential testing begins.
type UnauthChecker interface {
	// CheckUnauth probes the target for unauthenticated access.
	// Returns a Result with:
	//   - Success=true, Banner contains finding: unauthenticated access confirmed
	//   - Success=false: service requires authentication (normal)
	CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg PluginConfig) *Result
}

// UnauthOnlyChecker is for services that only support unauthenticated access
// detection with no credential testing (e.g., Docker, Kubernetes).
type UnauthOnlyChecker interface {
	Name() string
	CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg PluginConfig) *Result
}

// PluginFactory is a function that creates a new Plugin instance.
// Using a factory pattern ensures each call to Get returns a fresh instance,
// which is important for concurrent usage.
type PluginFactory func() Plugin

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

	// BadkeysOnly mode: only load bad SSH keys, skip wordlists entirely
	if c.BadkeysOnly {
		if c.Protocol == "ssh" && !hasCreds && !hasKeys {
			for _, k := range badkeys.GetSSHCredentials() {
				c.Credentials = append(c.Credentials, Credential{Username: k.Username, Key: k.Key})
			}
		}
		return
	}

	// Load SSH badkeys as paired credentials when no keys/creds were provided
	if c.Protocol == "ssh" && !c.NoBadkeys && !hasCreds && !hasKeys {
		for _, k := range badkeys.GetSSHCredentials() {
			c.Credentials = append(c.Credentials, Credential{Username: k.Username, Key: k.Key})
		}
	}

	// Load wordlist defaults when no user-supplied credentials were provided
	if !hasCreds && !hasPasswords && !hasKeys {
		mode := c.Mode
		if mode == "" {
			mode = ModeDefault
		}
		if defaults := DefaultCredentialsForMode(c.Protocol, mode); len(defaults) > 0 {
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

// BruteWithContext executes a brute force attack using the provided configuration and context.
//
// The context can be used to cancel the operation early via context cancellation.
// The plugin is resolved once via GetPlugin and shared across all worker goroutines.
// See the Plugin interface documentation for thread-safety requirements.
func BruteWithContext(ctx context.Context, cfg *Config) ([]Result, error) {
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

	// 3. Run worker pool with provided context
	results, err := runWorkers(ctx, cfg, plug)
	if err != nil {
		return results, fmt.Errorf("brute force failed: %w", err)
	}

	return results, nil
}

// CheckUnauthAccess probes a target for unauthenticated access.
// For protocols that implement UnauthChecker (postgresql, redis, elasticsearch),
// it resolves the standard plugin and calls CheckUnauth.
// For unauth-only protocols (docker, kubernetes), it resolves from the
// unauth registry. Returns nil if the protocol does not support unauth checking.
func CheckUnauthAccess(ctx context.Context, target, protocol string, timeout time.Duration, pluginCfg PluginConfig) *Result {
	// Try the standard plugin registry first
	if plug, err := GetPlugin(protocol); err == nil {
		if checker, ok := plug.(UnauthChecker); ok {
			return checker.CheckUnauth(ctx, target, timeout, pluginCfg)
		}
		return nil
	}

	// Try the unauth-only registry
	if checker, err := GetUnauthChecker(protocol); err == nil {
		return checker.CheckUnauth(ctx, target, timeout, pluginCfg)
	}

	return nil
}

// Brute executes a brute force attack using the provided configuration.
//
// This is a convenience wrapper around BruteWithContext that uses context.Background().
// For cancellable operations, use BruteWithContext directly.
//
// The plugin is resolved once via GetPlugin and shared across all worker goroutines.
// See the Plugin interface documentation for thread-safety requirements.
func Brute(cfg *Config) ([]Result, error) {
	return BruteWithContext(context.Background(), cfg)
}
