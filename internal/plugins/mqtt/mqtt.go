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

package mqtt

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	defaultPort = "1883"
	clientID    = "brutus"

	packetConnect = 0x10
	packetConnack = 0x20

	protoLevel311 = 0x04

	flagCleanSession = 0x02
	flagPassword     = 0x40
	flagUsername     = 0x80

	codeAccepted      = 0
	codeBadUserOrPass = 4
	codeNotAuthorized = 5
)

var mqttAuthIndicators = []string{
	"not authorized",
	"bad user name or password",
	"bad username or password",
	"connack 4",
	"connack 5",
}

func init() {
	brutus.Register("mqtt", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements MQTT password authentication via CONNECT/CONNACK.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "mqtt"
}

// Test attempts MQTT CONNECT authentication using the provided credentials.
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("mqtt", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	code, err := p.connect(ctx, target, username, password, timeout, pluginCfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	switch code {
	case codeAccepted:
		result.Success = true
	case codeBadUserOrPass, codeNotAuthorized:
		result.Error = nil
	default:
		result.Error = fmt.Errorf("connection error: mqtt connack %d", code)
	}
	return result
}

// CheckUnauth probes for MQTT that accepts CONNECT with no credentials.
func (p *Plugin) CheckUnauth(ctx context.Context, target string, timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("mqtt", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	code, err := p.connect(ctx, target, "", "", timeout, pluginCfg)
	if err != nil || code != codeAccepted {
		return result
	}
	result.Success = true
	result.Banner = "[CRITICAL] MQTT accessible without authentication"
	return result
}

func (p *Plugin) connect(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) (byte, error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	addr := net.JoinHostPort(host, port)

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, pluginCfg.ProxyURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()

	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		tlsCfg.ServerName = host
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		conn = tconn
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	if _, err := conn.Write(encodeConnect(username, password)); err != nil {
		return 0, err
	}
	return readConnack(conn)
}

func encodeConnect(username, password string) []byte {
	var flags byte = flagCleanSession
	payload := encodeMQTTString(clientID)
	if username != "" || password != "" {
		flags |= flagUsername
		payload = append(payload, encodeMQTTString(username)...)
		if password != "" {
			flags |= flagPassword
			payload = append(payload, encodeMQTTString(password)...)
		}
	}

	vh := encodeMQTTString("MQTT")
	vh = append(vh, protoLevel311, flags, 0x00, 0x3c)
	body := append(vh, payload...)
	pkt := []byte{packetConnect}
	pkt = append(pkt, encodeRemainingLength(len(body))...)
	return append(pkt, body...)
}

func encodeMQTTString(s string) []byte {
	b := []byte(s)
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	return out
}

func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		encoded := byte(n % 128)
		n /= 128
		if n > 0 {
			encoded |= 0x80
		}
		out = append(out, encoded)
		if n == 0 {
			break
		}
	}
	return out
}

func readConnack(r io.Reader) (byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, err
	}
	if hdr[0]&0xF0 != packetConnack {
		return 0, fmt.Errorf("expected CONNACK, got 0x%02x", hdr[0])
	}
	remaining := int(hdr[1])
	if remaining < 2 {
		return 0, fmt.Errorf("short CONNACK remaining length %d", remaining)
	}
	body := make([]byte, remaining)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, err
	}
	return body[1], nil
}

var classifyError = brutus.NewClassifier(mqttAuthIndicators)
