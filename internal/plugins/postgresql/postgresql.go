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

package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("postgresql", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements PostgreSQL password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "postgresql"
}

// Test attempts PostgreSQL password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "postgresql",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target to extract host and port
	host, port := parseTarget(target)

	// Build PostgreSQL connection string
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s sslmode=disable connect_timeout=%d",
		username, password, host, port, int(timeout.Seconds()))

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer db.Close()

	// Create context with timeout
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Test connection with Ping
	err = db.PingContext(pingCtx)
	if err != nil {
		result.Error = classifyAuthError(err)
		result.Duration = time.Since(start)
		return result
	}

	// Success
	result.Success = true
	result.Duration = time.Since(start)
	return result
}

// parseTarget splits target into host and port.
// If no port is specified, defaults to 5432.
func parseTarget(target string) (host, port string) {
	// Check if target contains port
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1]
	}
	// Default to port 5432 if not specified
	return target, "5432"
}

// classifyError classifies database connection errors.
// All connection errors are wrapped as connection errors.
func classifyError(err error) error {
	return fmt.Errorf("connection error: %w", err)
}

// classifyAuthError classifies PostgreSQL authentication errors.
//
// Auth failure indicators (return nil):
// - "password authentication failed"
// - "role" + "does not exist"
//
// All other errors are connection problems (return wrapped error).
func classifyAuthError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication failure indicators
	authFailures := []string{
		"password authentication failed",
		"role",
	}

	for _, indicator := range authFailures {
		if strings.Contains(errStr, indicator) {
			// Check for "does not exist" which indicates invalid username
			if strings.Contains(errStr, "does not exist") {
				// Username doesn't exist - this is still an auth failure
				return nil
			}
			// Password authentication failed - this is an auth failure
			if strings.Contains(errStr, "password authentication failed") {
				return nil
			}
		}
	}

	// All other errors are connection problems
	return fmt.Errorf("connection error: %w", err)
}
