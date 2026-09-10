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

package db2

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "50000"

var db2AuthIndicators = []string{
	"sql30082",
	"password invalid",
	"security mechanism",
	"userid is invalid",
	"authentication",
}

func init() {
	brutus.Register("db2", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "db2" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("db2", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeDSS(conn, buildEXCSAT()); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if _, err := readDSS(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if err := writeDSS(conn, buildACCSEC()); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if _, err := readDSS(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if err := writeDSS(conn, buildSECCHK(username, password)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	resp, err := readDSS(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	s := string(resp)
	switch {
	case bytes.Contains(resp, []byte{0x00, 0x00}) && !bytes.Contains(bytes.ToLower(resp), []byte("sql30082")):
		if bytes.Contains(bytes.ToLower(resp), []byte("sql30082")) || bytes.Contains(bytes.ToLower(resp), []byte("invalid")) {
			return result
		}
		result.Success = true
	case bytes.Contains(bytes.ToLower(resp), []byte("sql30082")), bytes.Contains(bytes.ToLower(resp), []byte("password")):
	default:
		_ = s
		result.Error = classifyError(fmt.Errorf("db2 secchk response"))
	}
	return result
}

func buildEXCSAT() []byte {
	return ddm(0x1041, []byte{0x11, 0x47, 0x00, 0x01})
}

func buildACCSEC() []byte {
	return ddm(0x106D, []byte{0x11, 0xA2, 0x00, 0x04}) // SECMEC USRIDPWD
}

func buildSECCHK(user, pass string) []byte {
	var inner []byte
	inner = append(inner, 0x11, 0xA2, 0x00, 0x04)
	inner = append(inner, ebcdicParam(0x11, 0xA0, user)...)
	inner = append(inner, ebcdicParam(0x11, 0xA1, pass)...)
	return ddm(0x106E, inner)
}

func ebcdicParam(c0, c1 byte, s string) []byte {
	b := []byte(s)
	out := []byte{c0, c1, byte(len(b))}
	return append(out, b...)
}

func ddm(code uint16, payload []byte) []byte {
	n := 10 + len(payload)
	buf := make([]byte, n)
	binary.BigEndian.PutUint16(buf[0:2], uint16(n))
	buf[2] = 0xD0
	buf[3] = 0x01
	binary.BigEndian.PutUint16(buf[4:6], 0x0001)
	binary.BigEndian.PutUint16(buf[6:8], uint16(4+len(payload)))
	binary.BigEndian.PutUint16(buf[8:10], code)
	copy(buf[10:], payload)
	return buf
}

func writeDSS(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func readDSS(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr)
	if n < 2 {
		return hdr, nil
	}
	rest := make([]byte, n-2)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	return append(hdr, rest...), nil
}

var classifyError = brutus.NewClassifier(db2AuthIndicators)
