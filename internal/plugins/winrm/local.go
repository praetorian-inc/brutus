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

package winrm

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/internal/winlocal"
)

// wireUser is the username string the WinRM library should send.
//
// The library splits DOMAIN\user and user@domain itself, and sends an empty
// domain when neither is present. An empty domain is not a local login: Windows
// can pass it through to a DC. Unqualified names are rewritten to
// COMPUTER\user after a challenge probe.
func (p *Plugin) wireUser(ctx context.Context, host string, port int, username string, timeout time.Duration) (string, error) {
	id := winlocal.Parse(username)
	if !id.Local {
		if strings.Contains(username, `\`) || strings.Contains(username, "@") {
			return username, nil
		}
		return id.Domain + `\` + id.User, nil
	}
	key := fmt.Sprintf("winrm|%s|%s", strconv.FormatBool(p.UseHTTPS), net.JoinHostPort(host, strconv.Itoa(port)))
	name, err := winlocal.Resolve(ctx, key, func(ctx context.Context) (string, error) {
		return probeComputer(ctx, host, port, p.UseHTTPS, timeout)
	})
	if err != nil {
		return "", err
	}
	return name + `\` + id.User, nil
}

func probeComputer(ctx context.Context, host string, port int, useHTTPS bool, timeout time.Duration) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}

	var rw net.Conn = conn
	if useHTTPS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // matches the WinRM plugin, which skips verification
			ServerName:         host,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return "", err
		}
		rw = tlsConn
	}

	token := base64.StdEncoding.EncodeToString(winlocal.NegotiateMessage())
	req := fmt.Sprintf("POST /wsman HTTP/1.1\r\nHost: %s\r\nAuthorization: Negotiate %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", addr, token)
	if _, err := io.WriteString(rw, req); err != nil {
		return "", err
	}
	challenge, err := readNegotiateChallenge(rw)
	if err != nil {
		return "", err
	}
	name, ok := winlocal.ComputerName(challenge)
	if !ok {
		return "", fmt.Errorf("local auth: server did not advertise a computer name")
	}
	return name, nil
}

func readNegotiateChallenge(conn net.Conn) ([]byte, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "401") {
		return nil, fmt.Errorf("local auth: expected 401 challenge, got %s", strings.TrimSpace(line))
	}
	tp := textproto.NewReader(br)
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	for _, v := range hdr.Values("WWW-Authenticate") {
		v = strings.TrimSpace(v)
		scheme, rest, ok := strings.Cut(v, " ")
		if !ok {
			continue
		}
		if !strings.EqualFold(scheme, "Negotiate") && !strings.EqualFold(scheme, "NTLM") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("local auth: NTLM challenge missing")
}
