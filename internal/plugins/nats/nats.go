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

package nats

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "4222"

var natsAuthIndicators = []string{
	"authorization violation",
	"authentication",
	"auth required",
}

func init() {
	brutus.Register("nats", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "nats" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("nats", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	ok, err := connect(ctx, target, username, password, timeout, pluginCfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = ok
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("nats", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	ok, err := connect(ctx, target, "", "", timeout, pluginCfg)
	if err != nil || !ok {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] NATS accessible without authentication"
	return result
}

func connect(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) (bool, error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		tlsCfg.ServerName = host
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return false, err
		}
		conn = tconn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(line, "INFO") {
		return false, fmt.Errorf("unexpected nats banner: %s", strings.TrimSpace(line))
	}

	opts := map[string]string{"verbose": "false", "pedantic": "false", "lang": "go", "version": "brutus"}
	if username != "" || password != "" {
		opts["user"] = username
		opts["pass"] = password
	}
	body, _ := json.Marshal(opts)
	if _, err := fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", body); err != nil {
		return false, err
	}
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		resp = strings.TrimSpace(resp)
		switch {
		case strings.HasPrefix(resp, "+OK"), strings.HasPrefix(resp, "PONG"):
			return true, nil
		case strings.HasPrefix(resp, "-ERR"):
			return false, fmt.Errorf("%s", resp)
		case strings.HasPrefix(resp, "INFO"):
			continue
		default:
			return false, fmt.Errorf("unexpected nats response: %s", resp)
		}
	}
}

var classifyError = brutus.NewClassifier(natsAuthIndicators)
