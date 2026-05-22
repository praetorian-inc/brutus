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
	"time"

	_ "github.com/lib/pq"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

var postgresqlAuthIndicators = []string{
	"password authentication failed",
	"role \"", // More specific: 'role "username" does not exist'
	"does not exist",
	"no pg_hba.conf entry", // Server config rejects connection for this user/host
}

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("postgresql", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Parse target to extract host and port
	host, port := brutus.ParseTarget(target, "5432")

	// Build PostgreSQL connection string.
	// Default to dbname=postgres (the system database that always exists),
	// consistent with how the MSSQL plugin defaults to database=master.
	// Without this, lib/pq defaults to dbname=<username> which fails when
	// no database matching the username has been created — PostgreSQL
	// rejects the connection before authentication even occurs.
	connStr := fmt.Sprintf("dbname=postgres user=%s password=%s host=%s port=%s sslmode=disable connect_timeout=%d",
		username, password, host, port, int(timeout.Seconds()))

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = db.Close() }()

	// Create context with timeout
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Test connection with Ping
	err = db.PingContext(pingCtx)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	// Success
	result.Success = true
	return result
}

// CheckUnauth probes for PostgreSQL trust authentication (no password required).
func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("postgresql", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "5432")

	connStr := fmt.Sprintf("dbname=postgres user=postgres password='' host=%s port=%s sslmode=disable connect_timeout=%d",
		host, port, int(timeout.Seconds()))

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return result
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		return result
	}

	result.Success = true
	result.Banner = "[CRITICAL] PostgreSQL trust authentication enabled - unauthenticated access as 'postgres' superuser"
	return result
}

var classifyError = brutus.NewClassifier(postgresqlAuthIndicators)
