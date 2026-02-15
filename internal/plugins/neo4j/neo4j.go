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

package neo4j

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("neo4j", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Neo4j password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "neo4j"
}

// Test attempts Neo4j password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "neo4j",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build Neo4j Bolt URI
	uri := fmt.Sprintf("bolt://%s", target)

	// Create authentication token
	auth := neo4j.BasicAuth(username, password, "")

	// Create driver with timeout context
	// Skip TLS verification to allow self-signed certs
	driver, err := neo4j.NewDriverWithContext(uri, auth, func(c *config.Config) {
		c.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	})
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer driver.Close(ctx)

	// Create context with timeout for verification
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Verify connectivity and authentication
	err = driver.VerifyConnectivity(verifyCtx)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// classifyError classifies Neo4j errors.
//
// Auth failure indicators (return nil):
// - "authentication failure"
// - "invalid credentials"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"authentication failure",
		"invalid credentials",
		"authentication failed",
		"auth",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			// This is an authentication failure, not a connection error
			return nil
		}
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
