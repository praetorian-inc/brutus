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

package opcua

import (
	"context"
	"net"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "4840"

var opcuaAuthIndicators = []string{
	"baduseraccessdenied",
	"badidentitytokenrejected",
	"badidentitytokeninvalid",
	"user access denied",
	"statusbaduseraccessdenied",
}

func init() {
	brutus.Register("opcua", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "opcua" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("opcua", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	err := connect(ctx, target, username, password, timeout, pluginCfg, false)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = true
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("opcua", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()
	if err := connect(ctx, target, "", "", timeout, pluginCfg, true); err != nil {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] OPC UA accessible with anonymous identity"
	return result
}

func connect(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig, anonymous bool) error {
	host, port := brutus.ParseTarget(target, defaultPort)
	endpoint := "opc.tcp://" + net.JoinHostPort(host, port)

	opts := []opcua.Option{
		opcua.DialTimeout(timeout),
		opcua.RequestTimeout(timeout),
		opcua.AutoReconnect(false),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.SecurityPolicy("None"),
	}
	if anonymous {
		opts = append(opts, opcua.AuthAnonymous())
	} else {
		opts = append(opts, opcua.AuthUsername(username, password))
	}

	c, err := opcua.NewClient(endpoint, opts...)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := c.Connect(dialCtx); err != nil {
		return err
	}
	_ = c.Close(dialCtx)
	return nil
}

var classifyError = brutus.NewClassifier(opcuaAuthIndicators)
