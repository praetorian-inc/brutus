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

package rsync

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "873"

func init() {
	brutus.Register("rsync", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "rsync" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("rsync", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	ok, unauth, err := handshake(ctx, target, username, password, timeout, pluginCfg)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if unauth {
		result.Success = true
		return result
	}
	result.Success = ok
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("rsync", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	_, unauth, err := handshake(ctx, target, "", "", timeout, pluginCfg)
	if err != nil || !unauth {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] rsync module accessible without authentication"
	return result
}

func handshake(ctx context.Context, target, module, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) (authed, open bool, err error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		return false, false, err
	}
	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		return false, false, fmt.Errorf("unexpected rsync greeting: %s", strings.TrimSpace(greeting))
	}
	if _, err := fmt.Fprintf(conn, "@RSYNCD: 31.0\n"); err != nil {
		return false, false, err
	}

	mod := module
	if mod == "" {
		mod = "#"
	}
	if _, err := fmt.Fprintf(conn, "%s\n", mod); err != nil {
		return false, false, err
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, false, err
	}
	resp = strings.TrimSpace(resp)
	switch {
	case strings.HasPrefix(resp, "@RSYNCD: OK"), strings.HasPrefix(resp, "@RSYNCD: EXIT"):
		return true, true, nil
	case strings.HasPrefix(resp, "@RSYNCD: AUTHREQD"):
		challenge := strings.TrimSpace(strings.TrimPrefix(resp, "@RSYNCD: AUTHREQD"))
		sum := md5.Sum([]byte(password + challenge))
		if _, err := fmt.Fprintf(conn, "%s %s\n", module, hex.EncodeToString(sum[:])); err != nil {
			return false, false, err
		}
		authResp, err := reader.ReadString('\n')
		if err != nil {
			return false, false, err
		}
		authResp = strings.TrimSpace(authResp)
		if strings.HasPrefix(authResp, "@RSYNCD: OK") {
			return true, false, nil
		}
		return false, false, nil
	default:
		return false, false, fmt.Errorf("unexpected rsync response: %s", resp)
	}
}
