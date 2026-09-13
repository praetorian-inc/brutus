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

package activemq

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "61616"

var amqAuthIndicators = []string{
	"user name or password is invalid",
	"authentication",
	"unauthorized",
	"invalid user",
}

func init() {
	brutus.Register("activemq", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "activemq" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("activemq", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	conn, err := brutus.DialWithProxy(ctx, "tcp", net.JoinHostPort(host, port), timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := writeFrame(conn, wireFormatInfo()); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if _, err := readFrame(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if err := writeFrame(conn, connectionInfo(username, password)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	frame, err := readFrame(conn)
	if err != nil {
		result.Error = classifyError(err)
		return result
	}
	s := strings.ToLower(string(frame))
	switch {
	case strings.Contains(s, "exception") || strings.Contains(s, "invalid") || strings.Contains(s, "unauthorized"):
		result.Error = classifyError(fmt.Errorf("%s", s))
	case strings.Contains(s, "error"):
		result.Error = classifyError(fmt.Errorf("%s", s))
	default:
		result.Success = true
	}
	return result
}

func wireFormatInfo() []byte {
	// OpenWire WireFormatInfo command type 1
	var b bytes.Buffer
	b.WriteByte(1)
	writeOpenWireString(&b, "ActiveMQ")
	var mag [8]byte
	binary.BigEndian.PutUint32(mag[4:], 12)
	b.Write(mag[:])
	return b.Bytes()
}

func connectionInfo(user, pass string) []byte {
	var b bytes.Buffer
	b.WriteByte(3) // ConnectionInfo
	writeOpenWireString(&b, "brutus-conn")
	writeOpenWireString(&b, "brutus")
	writeOpenWireString(&b, user)
	writeOpenWireString(&b, pass)
	writeOpenWireString(&b, "")
	return b.Bytes()
}

func writeOpenWireString(w *bytes.Buffer, s string) {
	if s == "" {
		w.WriteByte(0)
		return
	}
	w.WriteByte(1)
	_ = binary.Write(w, binary.BigEndian, int16(len(s)))
	w.WriteString(s)
}

func writeFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > 1<<20 {
		return nil, fmt.Errorf("activemq frame too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

var classifyError = brutus.NewClassifier(amqAuthIndicators)
