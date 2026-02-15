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

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("mysql", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements MySQL password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "mysql"
}

// Test attempts MySQL password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "mysql",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Read TLS mode from context
	tlsMode := brutus.TLSModeFromContext(ctx)

	// Determine TLS parameter based on mode
	var tlsParam string
	switch tlsMode {
	case "verify":
		tlsParam = "tls=true"
	case "skip-verify":
		tlsParam = "tls=skip-verify"
	default: // "disable"
		tlsParam = "tls=false"
	}

	// Create DSN (Data Source Name)
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/?%s", username, password, target, tlsParam)

	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer db.Close()

	// Set connection timeout
	db.SetConnMaxLifetime(timeout)
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	// Create context with timeout
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Test connection with ping
	err = db.PingContext(pingCtx)
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

// classifyError classifies MySQL errors.
//
// Auth failure indicators (return nil):
// - "Access denied for user"
// - "authentication failed"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authentication failure indicators
	authFailures := []string{
		"Access denied for user",
		"authentication failed",
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
