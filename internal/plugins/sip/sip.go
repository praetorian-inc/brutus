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

package sip

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "5060"

func init() {
	brutus.Register("sip", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "sip" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("sip", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)
	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	callID := randomHex(8)
	branch := "z9hG4bK" + randomHex(8)
	req := registerRequest(host, port, username, callID, branch, 1, "")
	if _, err := io.WriteString(conn, req); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	status, headers, err := readSIP(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if status == 200 {
		result.Success = true
		return result
	}
	if status != 401 && status != 407 {
		if status == 403 || status == 404 {
			return result
		}
		result.Error = fmt.Errorf("connection error: sip status %d", status)
		return result
	}

	www := headers["www-authenticate"]
	if www == "" {
		www = headers["proxy-authenticate"]
	}
	auth := parseAuth(www)
	resp := digestResponse(username, password, "REGISTER", "sip:"+host, auth)
	authHdr := fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q, algorithm=MD5`,
		username, auth["realm"], auth["nonce"], "sip:"+host, resp)
	if auth["opaque"] != "" {
		authHdr += fmt.Sprintf(`, opaque=%q`, auth["opaque"])
	}
	req = registerRequest(host, port, username, callID, branch, 2, authHdr)
	if _, err := io.WriteString(conn, req); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	status, _, err = readSIP(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	switch status {
	case 200:
		result.Success = true
	case 401, 403, 407, 404:
	default:
		result.Error = fmt.Errorf("connection error: sip status %d", status)
	}
	return result
}

func registerRequest(host, port, user, callID, branch string, cseq int, auth string) string {
	uri := "sip:" + host
	if port != defaultPort {
		uri = "sip:" + net.JoinHostPort(host, port)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "REGISTER %s SIP/2.0\r\n", uri)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP %s;branch=%s\r\n", net.JoinHostPort(host, port), branch)
	fmt.Fprintf(&b, "From: <%s:%s@%s>;tag=%s\r\n", "sip", user, host, randomHex(6))
	fmt.Fprintf(&b, "To: <%s:%s@%s>\r\n", "sip", user, host)
	fmt.Fprintf(&b, "Call-ID: %s@%s\r\n", callID, host)
	fmt.Fprintf(&b, "CSeq: %d REGISTER\r\n", cseq)
	fmt.Fprintf(&b, "Contact: <sip:%s@%s>\r\n", user, host)
	b.WriteString("Expires: 60\r\nMax-Forwards: 70\r\nUser-Agent: brutus\r\n")
	if auth != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

func readSIP(conn net.Conn) (int, map[string]string, error) {
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("bad sip status line")
	}
	status, _ := strconv.Atoi(parts[1])
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if cl := headers["content-length"]; cl != "" {
		n, _ := strconv.Atoi(cl)
		if n > 0 {
			_, _ = io.CopyN(io.Discard, reader, int64(n))
		}
	}
	return status, headers, nil
}

func parseAuth(h string) map[string]string {
	out := map[string]string{}
	h = strings.TrimPrefix(h, "Digest ")
	for _, part := range strings.Split(h, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.ToLower(k)] = strings.Trim(v, `"`)
	}
	return out
}

func digestResponse(user, pass, method, uri string, auth map[string]string) string {
	ha1 := md5hex(user + ":" + auth["realm"] + ":" + pass)
	ha2 := md5hex(method + ":" + uri)
	return md5hex(ha1 + ":" + auth["nonce"] + ":" + ha2)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
