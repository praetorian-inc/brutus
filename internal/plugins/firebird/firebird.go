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

package firebird

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	defaultPort  = "3050"
	opConnect    = 1
	opAccept     = 3
	opReject     = 4
	opAttach     = 19
	opResponse   = 9
	opCondAccept = 20
	opAcceptData = 21
)

var firebirdAuthIndicators = []string{
	"your user name and password are not defined",
	"login",
	"password",
	"sqlcode = -902",
}

func init() {
	brutus.Register("firebird", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "firebird" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("firebird", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeConnect(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	op, err := readOp(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if op == opReject {
		result.Error = fmt.Errorf("connection error: firebird rejected protocol")
		return result
	}

	if err := writeAttach(conn, username, password); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	op, blob, err := readResponse(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	if op == opResponse {
		if len(blob) >= 12 {
			sqlcode := int32(binary.BigEndian.Uint32(blob[8:12]))
			if sqlcode != 0 {
				result.Error = classifyError(fmt.Errorf("firebird sqlcode %d", sqlcode))
				return result
			}
		}
		result.Success = true
		return result
	}
	result.Error = fmt.Errorf("connection error: firebird op %d", op)
	return result
}

func writeConnect(w io.Writer) error {
	// op_connect, op_attach, version, architecture, filename, protocols
	var b []byte
	b = appendInt(b, opConnect)
	b = appendInt(b, opAttach)
	b = appendInt(b, 3) // version 3
	b = appendInt(b, 1) // generic arch
	b = appendString(b, "")
	b = appendInt(b, 1) // 1 protocol
	b = appendInt(b, 10)
	b = appendInt(b, 1)
	b = appendInt(b, 2)
	b = appendInt(b, 3)
	b = appendInt(b, 2)
	return writeAll(w, b)
}

func writeAttach(w io.Writer, user, pass string) error {
	dpb := []byte{1}               // isc_dpb_version1
	dpb = appendDPB(dpb, 28, user) // user_name
	dpb = appendDPB(dpb, 29, pass) // password
	var b []byte
	b = appendInt(b, opAttach)
	b = appendInt(b, 0)
	b = appendString(b, "employee")
	b = appendBytes(b, dpb)
	return writeAll(w, b)
}

func appendInt(b []byte, v int) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(v))
	return append(b, n[:]...)
}

func appendString(b []byte, s string) []byte {
	return appendBytes(b, []byte(s))
}

func appendBytes(b, s []byte) []byte {
	b = appendInt(b, len(s))
	b = append(b, s...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func appendDPB(b []byte, typ byte, val string) []byte {
	b = append(b, typ, byte(len(val)))
	return append(b, val...)
}

func readOp(r io.Reader) (int, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return 0, err
	}
	return int(n), nil
}

func readResponse(r io.Reader) (int, []byte, error) {
	op, err := readOp(r)
	if err != nil {
		return 0, nil, err
	}
	buf := make([]byte, 32)
	n, _ := io.ReadFull(r, buf)
	return op, buf[:n], nil
}

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

var classifyError = brutus.NewClassifier(firebirdAuthIndicators)
