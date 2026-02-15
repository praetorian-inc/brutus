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

package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func init() {
	brutus.Register("mssql", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements MSSQL password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "mssql"
}

// Test attempts MSSQL password authentication using the provided credentials.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "mssql",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Build MSSQL connection string
	// Format: sqlserver://username:password@host:port?database=master
	// TrustServerCertificate=true and encrypt=disable allow connections without cert validation
	connStr := fmt.Sprintf("sqlserver://%s:%s@%s?database=master&connection+timeout=%d&encrypt=disable&TrustServerCertificate=true",
		username, password, target, int(timeout.Seconds()))

	// Open database connection
	db, err := sql.Open("sqlserver", connStr)
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

// classifyError classifies MSSQL errors.
//
// Auth failure indicators (return nil):
// - "Login failed for user"
//
// All other errors are connection problems (return wrapped error).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for authentication failure indicators
	authFailures := []string{
		"Login failed for user",
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
