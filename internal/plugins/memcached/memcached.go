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

package memcached

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	defaultPort    = "11211"
	magicReq       = 0x80
	opcodeSASLAuth = 0x21
	statusAuthErr  = 0x20
	statusSuccess  = 0x00
)

func init() {
	brutus.Register("memcached", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "memcached" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("memcached", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	conn, err := dial(ctx, target, timeout, pluginCfg)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	mech := []byte("PLAIN")
	payload := append(append(append([]byte{0}, []byte(username)...), 0), []byte(password)...)
	pkt := make([]byte, 24+len(mech)+len(payload))
	pkt[0] = magicReq
	pkt[1] = opcodeSASLAuth
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(mech)))
	binary.BigEndian.PutUint32(pkt[8:12], uint32(len(mech)+len(payload)))
	copy(pkt[24:], mech)
	copy(pkt[24+len(mech):], payload)
	if _, err := conn.Write(pkt); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	status := binary.BigEndian.Uint16(hdr[6:8])
	bodyLen := binary.BigEndian.Uint32(hdr[8:12])
	if bodyLen > 0 {
		_, _ = io.CopyN(io.Discard, conn, int64(bodyLen))
	}
	switch status {
	case statusSuccess:
		result.Success = true
	case statusAuthErr:
		result.Error = nil
	default:
		result.Error = fmt.Errorf("connection error: memcached status 0x%04x", status)
	}
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("memcached", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	conn, err := dial(ctx, target, timeout, pluginCfg)
	if err != nil {
		return result
	}
	defer func() { _ = conn.Close() }()

	if _, err := fmt.Fprintf(conn, "version\r\n"); err != nil {
		return result
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return result
	}
	if strings.HasPrefix(strings.ToUpper(line), "VERSION") {
		result.Success = true
		result.Banner = "[CRITICAL] Memcached accessible without authentication"
	}
	return result
}

func dial(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) (net.Conn, error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}
