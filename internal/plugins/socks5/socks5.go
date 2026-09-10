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

package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	defaultPort = "1080"
	ver         = 0x05
	methodUser  = 0x02
	authVer     = 0x01
	authOK      = 0x00
)

func init() {
	brutus.Register("socks5", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "socks5" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("socks5", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{ver, 0x01, methodUser}); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if reply[0] != ver || reply[1] != methodUser {
		result.Error = fmt.Errorf("connection error: socks5 method 0x%02x", reply[1])
		return result
	}

	u, pw := []byte(username), []byte(password)
	req := make([]byte, 0, 3+len(u)+len(pw))
	req = append(req, authVer, byte(len(u)))
	req = append(req, u...)
	req = append(req, byte(len(pw)))
	req = append(req, pw...)
	if _, err := conn.Write(req); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if auth[1] == authOK {
		result.Success = true
	}
	return result
}
