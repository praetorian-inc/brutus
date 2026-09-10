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

package kafka

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
	defaultPort      = "9092"
	apiSaslHandshake = 17
	apiSaslAuth      = 36
	saslHandshakeV1  = 1
	saslAuthV1       = 1
)

var kafkaAuthIndicators = []string{
	"sasl authentication failed",
	"authentication failed",
	"illegal sasl",
	"invalid credentials",
	"unauthorized",
}

func init() {
	brutus.Register("kafka", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "kafka" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("kafka", target, username, password)
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

	if err := writeRequest(conn, apiSaslHandshake, saslHandshakeV1, 1, encodeString("PLAIN")); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	body, err := readResponse(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if len(body) < 2 {
		result.Error = fmt.Errorf("connection error: short sasl handshake")
		return result
	}
	errCode := int16(binary.BigEndian.Uint16(body[0:2]))
	if errCode != 0 {
		result.Error = fmt.Errorf("connection error: kafka sasl handshake %d", errCode)
		return result
	}

	plain := append(append(append([]byte{0}, []byte(username)...), 0), []byte(password)...)
	if err := writeRequest(conn, apiSaslAuth, saslAuthV1, 2, encodeBytes(plain)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	body, err = readResponse(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	if len(body) < 2 {
		result.Error = fmt.Errorf("connection error: short sasl auth")
		return result
	}
	errCode = int16(binary.BigEndian.Uint16(body[0:2]))
	if errCode == 0 {
		result.Success = true
		return result
	}
	if errCode == 58 || errCode == 72 || errCode == 13 {
		return result
	}
	result.Error = fmt.Errorf("connection error: kafka sasl %d", errCode)
	return result
}

func writeRequest(w io.Writer, apiKey, apiVer, corr int16, body []byte) error {
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(apiKey))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(apiVer))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(corr))
	binary.BigEndian.PutUint16(hdr[8:10], 6)
	client := append(hdr, []byte("brutus")...)
	pkt := make([]byte, 4+len(client)+len(body))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(len(client)+len(body)))
	copy(pkt[4:], client)
	copy(pkt[4+len(client):], body)
	_, err := w.Write(pkt)
	return err
}

func readResponse(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n < 4 || n > 1<<20 {
		return nil, fmt.Errorf("bad kafka frame size %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf[4:], nil
}

func encodeString(s string) []byte {
	b := []byte(s)
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	return out
}

func encodeBytes(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

var classifyError = brutus.NewClassifier(kafkaAuthIndicators)
