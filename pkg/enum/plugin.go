// pkg/enum/plugin.go
package enum

import (
	"context"
	"time"
)

// Confidence represents the certainty level of an enumeration result.
type Confidence string

const (
	// ConfidenceHigh indicates the service gave a definitive response.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates a likely match based on response patterns.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates a possible match that may be a false positive.
	ConfidenceLow Confidence = "low"
)

// Result represents the outcome of checking one email against one service.
//
// Error convention (mirrors pkg/brutus):
//   - Account exists: Exists=true, Error=nil
//   - Account doesn't exist: Exists=false, Error=nil
//   - Service error: Exists=false, Error!=nil
type Result struct {
	Service    string        // service name (e.g., "microsoft365")
	Email      string        // email tested
	Exists     bool          // account exists on this service?
	Confidence Confidence    // high/medium/low
	Error      error         // service/connection error (nil = clean check)
	Duration   time.Duration // check duration
}

// OracleResult represents whether a service acts as an enumeration oracle.
type OracleResult struct {
	Service    string     // service name
	IsOracle   bool       // does this service differentiate valid/invalid accounts?
	Confidence Confidence // certainty of oracle detection
	Method     string     // detection method: "status_code", "response_body", "timing", "error_message"
	Error      error      // service error
}

// Plugin defines the interface for SaaS account enumeration.
// Each plugin checks if an email account exists on a specific service.
//
// Thread Safety: Plugin instances may be shared across goroutines.
// Implementations MUST be safe for concurrent use (stateless is ideal).
type Plugin interface {
	// Name returns the service name (e.g., "microsoft365", "okta").
	Name() string

	// Check tests if an email account exists on this service.
	//
	// Returns Result with:
	//   - Exists=true, Error=nil: Account exists
	//   - Exists=false, Error=nil: Account does not exist
	//   - Exists=false, Error!=nil: Service/connection error
	Check(ctx context.Context, email string, timeout time.Duration) *Result
}

// OraclePlugin extends Plugin with oracle discovery capability.
// Plugins that implement this interface can calibrate by comparing
// responses for known-valid vs known-invalid emails.
type OraclePlugin interface {
	Plugin

	// Discover tests if this service acts as an enumeration oracle.
	// It compares the response for the knownValid email against a
	// generated invalid email to detect differentiating behavior.
	Discover(ctx context.Context, knownValid string, timeout time.Duration) *OracleResult
}

// PluginFactory creates a new Plugin instance.
// Each call returns a fresh instance for concurrent safety.
type PluginFactory func() Plugin
