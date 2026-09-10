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
	"context"
	"net"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "4222"

var natsAuthIndicators = []string{
	"authorization violation",
	"authentication",
	"auth required",
	"nats: authorization",
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

	err := connect(ctx, target, username, password, timeout, pluginCfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = true
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("nats", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()
	if err := connect(ctx, target, "", "", timeout, pluginCfg); err != nil {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] NATS accessible without authentication"
	return result
}

type proxyDialer struct {
	ctx     context.Context
	timeout time.Duration
	proxy   string
}

func (d proxyDialer) Dial(network, address string) (net.Conn, error) {
	return brutus.DialWithProxy(d.ctx, network, address, d.timeout, d.proxy)
}

func connect(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) error {
	host, port := brutus.ParseTarget(target, defaultPort)
	url := "nats://" + net.JoinHostPort(host, port)
	opts := []nats.Option{
		nats.Name("brutus"),
		nats.Timeout(timeout),
		nats.NoReconnect(),
		nats.DontRandomize(),
		nats.SetCustomDialer(proxyDialer{ctx: ctx, timeout: timeout, proxy: pluginCfg.ProxyURL}),
	}
	if username != "" || password != "" {
		opts = append(opts, nats.UserInfo(username, password))
	}
	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return err
	}
	nc.Close()
	return nil
}

var classifyError = brutus.NewClassifier(natsAuthIndicators)
