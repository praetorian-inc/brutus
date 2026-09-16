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
	"net"
	"net/url"
	"strconv"
	"time"

	mssql "github.com/denisenkom/go-mssqldb"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

type proxyDialer struct {
	dial brutus.ProxyDialFunc
}

func (d proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

// mssqlAuthIndicators contains strings that indicate authentication failures.
var mssqlAuthIndicators = []string{
	"Login failed for user",
}

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
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("mssql", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	connStr := mssqlURL(target, username, password, pluginCfg.TLSMode, timeout)

	var db *sql.DB
	if pluginCfg.ProxyURL != "" {
		dialFunc, err := brutus.NewProxyDialFunc(pluginCfg.ProxyURL, timeout)
		if err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}
		connector, err := mssql.NewConnector(connStr)
		if err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}
		connector.Dialer = proxyDialer{dial: dialFunc}
		db = sql.OpenDB(connector)
	} else {
		var err error
		db, err = sql.Open("sqlserver", connStr)
		if err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := db.PingContext(pingCtx)
	if err != nil {
		result.Error = brutus.ClassifyAuthError(err, mssqlAuthIndicators)
		return result
	}

	result.Success = true
	return result
}

func mssqlURL(target, username, password, tlsMode string, timeout time.Duration) string {
	host, port := brutus.ParseTarget(target, "1433")
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(host, port),
	}
	q := url.Values{}
	q.Set("database", "master")
	q.Set("connection timeout", strconv.Itoa(timeoutSec))
	encrypt := "disable"
	trust := "true"
	switch tlsMode {
	case "verify":
		encrypt = "true"
		trust = "false"
	case "skip-verify":
		encrypt = "true"
		trust = "true"
	}
	q.Set("encrypt", encrypt)
	q.Set("TrustServerCertificate", trust)
	u.RawQuery = q.Encode()
	return u.String()
}
