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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net"
	"sync"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

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

	dsn, err := mysqlDSN(target, username, password, pluginCfg.TLSMode, pluginCfg.ProxyURL, timeout)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(timeout)
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = db.PingContext(pingCtx)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}

	result.Success = true
	return result
}

func mysqlDSN(target, username, password, tlsMode, proxyURL string, timeout time.Duration) (string, error) {
	host, port := brutus.ParseTarget(target, "3306")
	tlsValue := "false"
	switch tlsMode {
	case "verify":
		tlsValue = "true"
	case "skip-verify":
		tlsValue = "skip-verify"
	}
	cfg := mysqldriver.NewConfig()
	cfg.User = username
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, port)
	cfg.TLSConfig = tlsValue
	if proxyURL != "" {
		netName, err := registerProxyDial(proxyURL, timeout)
		if err != nil {
			return "", err
		}
		cfg.Net = netName
	}
	return cfg.FormatDSN(), nil
}

type proxyDialReg struct {
	once    sync.Once
	netName string
	err     error
}

var proxyDials sync.Map // proxyURL -> *proxyDialReg

func proxyNetName(proxyURL string) string {
	sum := sha256.Sum256([]byte(proxyURL))
	return "brutus-socks-" + hex.EncodeToString(sum[:8])
}

func registerProxyDial(proxyURL string, timeout time.Duration) (string, error) {
	v, _ := proxyDials.LoadOrStore(proxyURL, &proxyDialReg{})
	reg := v.(*proxyDialReg)
	reg.once.Do(func() {
		if _, err := brutus.NewProxyDialFunc(proxyURL, timeout); err != nil {
			reg.err = err
			return
		}
		netName := proxyNetName(proxyURL)
		mysqldriver.RegisterDialContext(netName, func(ctx context.Context, addr string) (net.Conn, error) {
			d := timeout
			if deadline, ok := ctx.Deadline(); ok {
				if remaining := time.Until(deadline); remaining > 0 {
					d = remaining
				} else if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			dialFunc, err := brutus.NewProxyDialFunc(proxyURL, d)
			if err != nil {
				return nil, err
			}
			return dialFunc(ctx, "tcp", addr)
		})
		reg.netName = netName
	})
	if reg.err != nil {
		return "", reg.err
	}
	return reg.netName, nil
}

var mysqlAuthIndicators = []string{
	"Access denied for user",
	"authentication failed",
}

var classifyError = brutus.NewClassifier(mysqlAuthIndicators)
