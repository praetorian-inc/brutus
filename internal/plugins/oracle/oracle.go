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

package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// oracleAuthFailureIndicators are errors that mean the credentials are wrong.
// These map to Success=false, Error=nil per the Result convention.
var oracleAuthFailureIndicators = []string{
	"ORA-01017", // invalid username/password; logon denied
	"ORA-01005", // null password given; logon denied
	"ORA-28000", // the account is locked
}

// oracleAuthSuccessIndicators are errors that confirm the password is correct
// but access is restricted. These map to Success=true since the credential
// was validated by the server.
var oracleAuthSuccessIndicators = []string{
	"ORA-28001", // the password has expired (password was correct)
	"ORA-28009", // connection as SYS should be as SYSDBA or SYSOPER (password was correct)
	"ORA-01031", // insufficient privileges (password was correct)
}

// defaultServiceNames are tried in order when connecting to an Oracle target.
// The first service that accepts the connection (auth success or auth failure)
// is used; connection-level errors (unknown service) move to the next.
var defaultServiceNames = []string{
	"XE",       // Oracle Express Edition
	"XEPDB1",   // Oracle XE pluggable database
	"FREE",     // Oracle 23c Free
	"FREEPDB1", // Oracle 23c Free pluggable database
	"ORCL",     // Oracle Enterprise/Standard default
}

func init() {
	brutus.Register("oracle", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements Oracle Database password authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "oracle"
}

// Test attempts Oracle Database password authentication using the provided credentials.
// It tries each common service name until one connects successfully or returns an
// auth failure. If all service names fail with connection errors, the last error
// is returned.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "oracle",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	host, port := brutus.ParseTarget(target, "1521")
	userInfo := url.UserPassword(username, password).String()

	for _, service := range defaultServiceNames {
		connStr := fmt.Sprintf("oracle://%s@%s:%s/%s", userInfo, host, port, service)

		err := tryConnect(ctx, connStr, timeout)
		if err == nil {
			// Auth succeeded — clean login
			result.Success = true
			result.Duration = time.Since(start)
			return result
		}

		if isAuthSuccess(err) {
			// Password was correct but access is restricted
			// (expired password, insufficient privileges, SYS needs SYSDBA)
			result.Success = true
			result.Duration = time.Since(start)
			return result
		}

		classified := classifyError(err)
		if classified == nil {
			// Auth failure (wrong credentials) — the service exists,
			// so we have our answer: creds are wrong.
			result.Duration = time.Since(start)
			return result
		}

		// Connection error — this service name likely doesn't exist,
		// try the next one. Keep the error in case all fail.
		result.Error = classified
	}

	result.Duration = time.Since(start)
	return result
}

// tryConnect opens a database connection and pings it. Returns nil on success.
func tryConnect(ctx context.Context, connStr string, timeout time.Duration) error {
	db, err := sql.Open("oracle", connStr)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return db.PingContext(pingCtx)
}

// isAuthSuccess checks if the error indicates the password was correct
// but access is restricted (expired, insufficient privileges, etc.).
func isAuthSuccess(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	for _, indicator := range oracleAuthSuccessIndicators {
		if strings.Contains(errStr, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func classifyError(err error) error {
	return brutus.ClassifyAuthError(err, oracleAuthFailureIndicators)
}
