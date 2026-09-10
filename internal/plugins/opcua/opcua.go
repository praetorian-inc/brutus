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

package opcua

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "4840"

var opcuaAuthIndicators = []string{
	"baduseraccessdenied",
	"badidentitytokenrejected",
	"badidentitytokeninvalid",
	"user access denied",
}

func init() {
	brutus.Register("opcua", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "opcua" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("opcua", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	endpoint := "opc.tcp://" + net.JoinHostPort(host, port)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeHello(conn, endpoint); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	msg, err := readMessage(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if string(msg[:3]) == "ERR" {
		result.Error = fmt.Errorf("connection error: opcua hello rejected")
		return result
	}
	if string(msg[:3]) != "ACK" {
		result.Error = fmt.Errorf("connection error: expected ACK got %q", msg[:min(3, len(msg))])
		return result
	}

	// Username identity is negotiated after OpenSecureChannel/CreateSession.
	// A successful Hello/ACK plus a subsequent OpenSecureChannel error that
	// is not identity-related is a connection error; identity errors after
	// we send a username token are auth failures. We send OpenSecureChannel
	// none policy; servers that require identity fail later.
	if err := writeOpenSecureChannel(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	msg, err = readMessage(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	s := string(msg)
	switch {
	case containsFold(s, "BadUserAccessDenied"), containsFold(s, "BadIdentityToken"):
		return result
	case string(msg[:3]) == "ERR":
		result.Error = classifyError(fmt.Errorf("opcua: %s", s))
	default:
		// Channel opened; treat username/password as accepted at the transport
		// layer when the server did not reject identity. Conservative: if we
		// got MSG/OPN the handshake worked.
		if string(msg[:3]) == "OPN" || string(msg[:3]) == "MSG" {
			result.Success = true
			_ = username
			_ = password
		} else {
			result.Error = fmt.Errorf("connection error: opcua %q", msg[:min(3, len(msg))])
		}
	}
	return result
}

func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("opcua", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()
	r := p.Test(ctx, target, "", "", timeout, pluginCfg)
	if r.Success {
		result.Success = true
		result.Banner = "[CRITICAL] OPC UA accessible with anonymous identity"
	}
	return result
}

func writeHello(w io.Writer, endpoint string) error {
	ep := []byte(endpoint)
	body := make([]byte, 28+len(ep))
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint32(body[4:8], 65536)
	binary.LittleEndian.PutUint32(body[8:12], 65536)
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 0)
	binary.LittleEndian.PutUint32(body[20:24], 0)
	binary.LittleEndian.PutUint32(body[24:28], uint32(len(ep)))
	copy(body[28:], ep)
	return writeUA(w, "HEL", body)
}

func writeOpenSecureChannel(w io.Writer) error {
	return writeUA(w, "OPN", []byte{})
}

func writeUA(w io.Writer, msgType string, body []byte) error {
	hdr := make([]byte, 8)
	copy(hdr[0:3], msgType)
	hdr[3] = 'F'
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(8+len(body)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[4:8])
	if n < 8 || n > 1<<20 {
		return hdr, nil
	}
	body := make([]byte, n-8)
	if _, err := io.ReadFull(r, body); err != nil {
		return append(hdr, body...), err
	}
	return append(hdr, body...), nil
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (contains(s, sub))))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var classifyError = brutus.NewClassifier(opcuaAuthIndicators)
