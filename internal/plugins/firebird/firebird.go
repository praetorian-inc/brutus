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

package firebird

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"time"

	_ "github.com/nakagami/firebirdsql"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "3050"

var firebirdAuthIndicators = []string{
	"your user name and password are not defined",
	"login",
	"password",
	"sqlcode = -902",
	"authentication error",
}

func init() {
	brutus.Register("firebird", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "firebird" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("firebird", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	u := url.UserPassword(username, password)
	dsn := fmt.Sprintf("%s@%s/employee?timeout=%d", u.String(), net.JoinHostPort(host, port), int(timeout.Seconds()))
	if int(timeout.Seconds()) <= 0 {
		dsn = fmt.Sprintf("%s@%s/employee", u.String(), net.JoinHostPort(host, port))
	}

	db, err := sql.Open("firebirdsql", dsn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = db.Close() }()
	db.SetConnMaxLifetime(timeout)

	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(firebirdAuthIndicators)
