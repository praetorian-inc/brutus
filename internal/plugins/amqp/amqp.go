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

package amqp

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
	defaultPort = "5672"
	frameEnd    = 0xCE
	classConn   = 10
	methStart   = 10
	methStartOK = 11
	methTune    = 30
	methClose   = 50
	codeAuth    = 403
)

var amqpAuthIndicators = []string{
	"access-refused",
	"access refused",
	"403",
	"authentication failed",
	"login refused",
}

func init() {
	brutus.Register("amqp", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "amqp" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("amqp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	ok, err := handshake(ctx, target, username, password, timeout, pluginCfg)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	result.Success = ok
	return result
}

func handshake(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) (bool, error) {
	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	if tlsCfg := brutus.BuildTLSConfig(pluginCfg.TLSMode); tlsCfg != nil {
		tlsCfg.ServerName = host
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return false, err
		}
		conn = tconn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		return false, err
	}
	class, method, payload, err := readMethod(conn)
	if err != nil {
		return false, err
	}
	if class != classConn || method != methStart {
		return false, fmt.Errorf("expected connection.start, got %d/%d", class, method)
	}
	_ = payload

	resp := append([]byte{0}, append(append([]byte(username), 0), []byte(password)...)...)
	if err := writeStartOK(conn, resp); err != nil {
		return false, err
	}
	class, method, payload, err = readMethod(conn)
	if err != nil {
		return false, err
	}
	switch {
	case class == classConn && method == methTune:
		return true, nil
	case class == classConn && method == methClose:
		if len(payload) >= 2 {
			code := binary.BigEndian.Uint16(payload[:2])
			if code == codeAuth {
				return false, fmt.Errorf("ACCESS-REFUSED")
			}
		}
		return false, fmt.Errorf("amqp connection.close")
	default:
		return false, fmt.Errorf("unexpected amqp method %d/%d", class, method)
	}
}

func writeStartOK(w io.Writer, sasl []byte) error {
	var payload []byte
	payload = append(payload, encodeTable(map[string]string{"product": "brutus"})...)
	payload = append(payload, encodeShortStr("PLAIN")...)
	payload = append(payload, encodeLongStr(sasl)...)
	payload = append(payload, encodeShortStr("en_US")...)
	return writeMethod(w, classConn, methStartOK, payload)
}

func writeMethod(w io.Writer, class, method uint16, payload []byte) error {
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[0:2], class)
	binary.BigEndian.PutUint16(body[2:4], method)
	copy(body[4:], payload)
	hdr := []byte{1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(body)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	_, err := w.Write([]byte{frameEnd})
	return err
}

func readMethod(r io.Reader) (uint16, uint16, []byte, error) {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[3:7])
	body := make([]byte, n+1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	if body[n] != frameEnd {
		return 0, 0, nil, fmt.Errorf("bad amqp frame end")
	}
	if n < 4 {
		return 0, 0, nil, fmt.Errorf("short amqp method frame")
	}
	return binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4]), body[4:n], nil
}

func encodeShortStr(s string) []byte {
	b := []byte(s)
	return append([]byte{byte(len(b))}, b...)
}

func encodeLongStr(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func encodeTable(m map[string]string) []byte {
	var inner []byte
	for k, v := range m {
		inner = append(inner, encodeShortStr(k)...)
		inner = append(inner, 'S')
		inner = append(inner, encodeLongStr([]byte(v))...)
	}
	return encodeLongStr(inner)
}

var classifyError = brutus.NewClassifier(amqpAuthIndicators)
