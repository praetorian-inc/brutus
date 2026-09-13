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

package amqp

import (
	"context"
	"net"
	"net/url"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "5672"

var amqpAuthIndicators = []string{
	"access-refused",
	"access refused",
	"403",
	"authentication failed",
	"login refused",
	"invalid credentials",
}

func init() {
	brutus.Register("amqp", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "amqp" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("amqp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)
	scheme := "amqp"
	if pluginCfg.TLSMode == "verify" || pluginCfg.TLSMode == "skip-verify" {
		scheme = "amqps"
	}
	u := url.URL{Scheme: scheme, Host: addr, Path: "/"}

	cfg := amqp.Config{
		SASL: []amqp.Authentication{
			&amqp.PlainAuth{Username: username, Password: password},
		},
		Vhost:           "/",
		Heartbeat:       0,
		Locale:          "en_US",
		TLSClientConfig: brutus.BuildTLSConfig(pluginCfg.TLSMode),
		Dial: func(network, a string) (net.Conn, error) {
			return brutus.DialWithProxy(ctx, network, a, timeout, pluginCfg.ProxyURL)
		},
	}

	conn, err := amqp.DialConfig(u.String(), cfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	_ = conn.Close()
	result.Success = true
	return result
}

var classifyError = brutus.NewClassifier(amqpAuthIndicators)
