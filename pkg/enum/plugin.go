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

// PluginFactory creates a new Plugin instance.
// Each call returns a fresh instance for concurrent safety.
type PluginFactory func() Plugin
