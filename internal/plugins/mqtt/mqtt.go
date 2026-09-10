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

package mqtt

import (
	"context"
	"net"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "1883"

var mqttAuthIndicators = []string{
	"not authorized",
	"bad user name or password",
	"bad username or password",
	"not authorised",
}

func init() {
	brutus.Register("mqtt", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "mqtt" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("mqtt", target, username, password)
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
	result := brutus.NewResult("mqtt", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()
	if err := connect(ctx, target, "", "", timeout, pluginCfg); err != nil {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] MQTT accessible without authentication"
	return result
}

func connect(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) error {
	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)
	scheme := "tcp"
	if pluginCfg.TLSMode == "verify" || pluginCfg.TLSMode == "skip-verify" {
		scheme = "ssl"
	}

	opts := paho.NewClientOptions()
	opts.AddBroker(scheme + "://" + addr)
	opts.SetClientID("brutus")
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetConnectTimeout(timeout)
	opts.SetAutoReconnect(false)
	opts.SetConnectRetry(false)
	opts.SetKeepAlive(0)
	opts.SetPingTimeout(timeout)
	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		opts.SetTLSConfig(tlsCfg)
	}
	opts.SetDialer(&net.Dialer{Timeout: timeout})

	client := paho.NewClient(opts)
	token := client.Connect()
	if !token.WaitTimeout(timeout) {
		return context.DeadlineExceeded
	}
	if err := token.Error(); err != nil {
		return err
	}
	client.Disconnect(0)
	return nil
}

var classifyError = brutus.NewClassifier(mqttAuthIndicators)
