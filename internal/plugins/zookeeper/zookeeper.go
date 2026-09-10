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

package zookeeper

import (
	"context"
	"net"
	"time"

	"github.com/go-zookeeper/zk"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "2181"

var zkAuthIndicators = []string{
	"authentication failed",
	"not authenticated",
	"authfailed",
	"session expired",
	"zk: client authentication failed",
	"zk: not authenticated",
}

func init() {
	brutus.Register("zookeeper", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "zookeeper" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("zookeeper", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)
	conn, _, err := zk.Connect([]string{addr}, timeout, zk.WithDialer(func(network, address string, to time.Duration) (net.Conn, error) {
		return brutus.DialWithProxy(ctx, network, address, to, pluginCfg.ProxyURL)
	}))
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer conn.Close()

	if err := conn.AddAuth("digest", []byte(username+":"+password)); err != nil {
		result.Error = classifyError(err)
		return result
	}
	if _, _, err := conn.Exists("/"); err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = true
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("zookeeper", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	ok := zk.FLWRuok([]string{net.JoinHostPort(host, port)}, timeout)
	if len(ok) == 1 && ok[0] {
		result.Success = true
		result.Banner = "[CRITICAL] ZooKeeper accessible without authentication"
	}
	return result
}

var classifyError = brutus.NewClassifier(zkAuthIndicators)
