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

package kafka

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "9092"

var kafkaAuthIndicators = []string{
	"sasl authentication failed",
	"authentication failed",
	"illegal sasl",
	"invalid credentials",
	"unauthorized",
}

func init() {
	brutus.Register("kafka", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "kafka" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("kafka", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)
	tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode)

	d := &kafka.Dialer{
		ClientID:      "brutus",
		Timeout:       timeout,
		DualStack:     true,
		SASLMechanism: plain.Mechanism{Username: username, Password: password},
		DialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := brutus.DialWithProxy(ctx, network, address, timeout, pluginCfg.ProxyURL)
			if err != nil {
				return nil, err
			}
			_ = c.SetDeadline(time.Now().Add(timeout))
			if tlsCfg == nil {
				return c, nil
			}
			cfg := tlsCfg.Clone()
			if cfg.ServerName == "" {
				h, _, splitErr := net.SplitHostPort(address)
				if splitErr != nil {
					h = host
				}
				cfg.ServerName = h
			}
			tconn := tls.Client(c, cfg)
			if err := tconn.HandshakeContext(ctx); err != nil {
				_ = tconn.Close()
				return nil, err
			}
			return tconn, nil
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	_ = conn.Close()
	result.Success = true
	return result
}

func classifyError(err error) error {
	if errors.Is(err, kafka.SASLAuthenticationFailed) {
		return nil
	}
	return brutus.ClassifyAuthError(err, kafkaAuthIndicators)
}
