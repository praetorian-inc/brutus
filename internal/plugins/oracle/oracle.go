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
	"time"

	_ "github.com/sijms/go-ora/v2"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// oracleAuthIndicators contains strings that indicate authentication failures.
var oracleAuthIndicators = []string{
	"ORA-01017", // invalid username/password; logon denied
	"ORA-28000", // the account is locked
	"ORA-01005", // null password given; logon denied
	"ORA-28001", // the password has expired
	"ORA-28009", // connection as SYS should be as SYSDBA or SYSOPER
	"ORA-01031", // insufficient privileges
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
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "oracle",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	host, port := brutus.ParseTarget(target, "1521")

	// Build Oracle connection URL
	// Format: oracle://user:password@host:port/
	// url.UserPassword handles encoding of special characters in credentials
	connStr := fmt.Sprintf("oracle://%s@%s:%s/",
		url.UserPassword(username, password).String(),
		host, port)

	db, err := sql.Open("oracle", connStr)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer db.Close()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = db.PingContext(pingCtx)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		return result
	}

	result.Success = true
	result.Duration = time.Since(start)
	return result
}

func classifyError(err error) error {
	return brutus.ClassifyAuthError(err, oracleAuthIndicators)
}
