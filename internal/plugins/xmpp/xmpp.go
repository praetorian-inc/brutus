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

package xmpp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "5222"

var xmppAuthIndicators = []string{
	"not-authorized",
	"authentication failed",
	"invalid-authzid",
	"sasl",
}

func init() {
	brutus.Register("xmpp", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "xmpp" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("xmpp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		tlsCfg.ServerName = host
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}
		conn = tconn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	domain := host
	stream := fmt.Sprintf(`<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`, domain)
	if _, err := io.WriteString(conn, stream); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	buf, err := readSome(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	plain := []byte{0}
	plain = append(plain, []byte(username)...)
	plain = append(plain, 0)
	plain = append(plain, []byte(password)...)
	auth := fmt.Sprintf(`<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>%s</auth>`, base64.StdEncoding.EncodeToString(plain))
	if _, err := io.WriteString(conn, auth); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	buf, err = readSome(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	s := string(buf)
	switch {
	case strings.Contains(s, "<success"):
		result.Success = true
	case strings.Contains(s, "not-authorized"), strings.Contains(s, "<failure"):
		result.Error = nil
	default:
		result.Error = fmt.Errorf("connection error: unexpected xmpp response")
	}
	return result
}

func readSome(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

var classifyError = brutus.NewClassifier(xmppAuthIndicators)
