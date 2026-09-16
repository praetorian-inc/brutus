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
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// skipVerifyTLSKey names the pq custom TLS config registered for skip-verify
// mode. lib/pq's built-in sslmode=require silently upgrades to CA verification
// (matching sslmode=verify-ca) whenever a root CA file is found at the default
// ~/.postgresql/root.crt location, so it can't be relied on to truly skip
// verification. Registering an explicit InsecureSkipVerify config and
// selecting it via sslmode=pqgo-<key> bypasses that fallback.
const skipVerifyTLSKey = "brutus-skip-verify"

var registerSkipVerifyTLS = sync.OnceFunc(func() {
	_ = pq.RegisterTLSConfig(skipVerifyTLSKey, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // user explicitly chose skip-verify
})

// postgresqlAuthIndicators lists error fragments that mean the credentials
// themselves were rejected (authentication failure). Matching one causes the
// error to be classified as invalid credentials.
//
// Post-authentication errors are deliberately excluded so that VALID
// credentials are never silently discarded:
//   - `database "X" does not exist` and `permission denied for database "X"`
//     are only returned AFTER the server accepts the credentials, so they are
//     treated as connection errors rather than invalid credentials.
var postgresqlAuthIndicators = []string{
	"password authentication failed",
	`role "`, // 'role "username" does not exist'
	"no pg_hba.conf entry",
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

// sslMode maps a brutus TLS mode ("verify", "skip-verify", "disable") to the
// equivalent lib/pq sslmode connection parameter.
func sslMode(tlsMode string) string {
	switch tlsMode {
	case "verify":
		return "verify-full"
	case "skip-verify":
		registerSkipVerifyTLS()
		return "pqgo-" + skipVerifyTLSKey
	default: // "disable"
		return "disable"
	}
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

	host, port := brutus.ParseTarget(target, "5432")

	connStr := postgresURL(host, port, username, password, pluginCfg.TLSMode, timeout)

	db, err := openPostgres(connStr, pluginCfg.ProxyURL, timeout)
	if err != nil {
		result.Error = classifyError(scrubError(err, connStr, password))
		return result
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = db.PingContext(pingCtx)
	if err != nil {
		result.Error = classifyError(scrubError(err, connStr, password))
		return result
	}

	result.Success = true
	return result
}

// CheckUnauth probes for PostgreSQL trust authentication (no password required).
func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("postgresql", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "5432")

	connStr := postgresURL(host, port, "postgres", "", pluginCfg.TLSMode, timeout)

	db, err := openPostgres(connStr, pluginCfg.ProxyURL, timeout)
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

func postgresURL(host, port, username, password, tlsMode string, timeout time.Duration) string {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Host:   net.JoinHostPort(host, port),
		Path:   "/postgres",
	}
	q := url.Values{}
	q.Set("sslmode", sslMode(tlsMode))
	q.Set("connect_timeout", strconv.Itoa(timeoutSec))
	u.RawQuery = q.Encode()
	return u.String()
}

func openPostgres(dsn, proxyURL string, timeout time.Duration) (*sql.DB, error) {
	if proxyURL == "" {
		return sql.Open("postgres", dsn)
	}

	dialFunc, err := brutus.NewProxyDialFunc(proxyURL, timeout)
	if err != nil {
		return nil, err
	}

	connector, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	connector.Dialer(pqProxyDialer{dial: dialFunc})
	return sql.OpenDB(connector), nil
}

type pqProxyDialer struct {
	dial brutus.ProxyDialFunc
}

func (d pqProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func (d pqProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(context.Background(), network, address)
}

func (d pqProxyDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.dial(ctx, network, address)
}

var (
	_ pq.Dialer        = pqProxyDialer{}
	_ pq.DialerContext = pqProxyDialer{}
)

func scrubError(err error, dsn, password string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	orig := msg
	if dsn != "" {
		msg = strings.ReplaceAll(msg, dsn, "REDACTED")
	}
	if password != "" {
		msg = strings.ReplaceAll(msg, password, "REDACTED")
	}
	if msg == orig {
		return err
	}
	return errors.New(msg)
}

var classifyError = brutus.NewClassifier(postgresqlAuthIndicators)
