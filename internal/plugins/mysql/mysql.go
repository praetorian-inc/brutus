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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("mysql", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Read TLS mode from context
	tlsMode := pluginCfg.TLSMode

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
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = db.Close() }()

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
		return result
	}

	// Success
	result.Success = true
	return result
}

// MySQL-specific auth failure indicators
var mysqlAuthIndicators = []string{
	"Access denied for user",
	"authentication failed",
}

var classifyError = brutus.NewClassifier(mysqlAuthIndicators)
