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

package ipmi

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const defaultPort = "623"

func init() {
	brutus.Register("ipmi", func() brutus.Plugin { return &Plugin{} })
}

type Plugin struct{}

func (p *Plugin) Name() string { return "ipmi" }

func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()
	result := brutus.NewResult("ipmi", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, defaultPort)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := send(conn, getChannelAuthCap()); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	if _, err := recv(conn); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	if err := send(conn, getSessionChallenge(username)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	chal, err := recv(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	ipmi := extractIPMI(chal)
	if len(ipmi) < 24 {
		result.Error = fmt.Errorf("connection error: short ipmi challenge")
		return result
	}
	cc := ipmi[6]
	if cc != 0 {
		if cc == 0x81 || cc == 0x82 {
			return result
		}
		result.Error = fmt.Errorf("connection error: ipmi cc 0x%02x", cc)
		return result
	}
	sessionID := binary.LittleEndian.Uint32(ipmi[7:11])
	challenge := ipmi[11:27]

	if err := send(conn, activateSession(sessionID, challenge, password)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	act, err := recv(conn)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	ipmi = extractIPMI(act)
	if len(ipmi) < 7 {
		result.Error = fmt.Errorf("connection error: short ipmi activate")
		return result
	}
	switch ipmi[6] {
	case 0:
		result.Success = true
	case 0x81, 0x82, 0x83:
	default:
		result.Error = fmt.Errorf("connection error: ipmi activate cc 0x%02x", ipmi[6])
	}
	return result
}

func rmcp(ipmi []byte) []byte {
	pkt := []byte{0x06, 0x00, 0xff, 0x07}
	return append(pkt, ipmi...)
}

func ipmiHdr(netFn, cmd byte, data []byte) []byte {
	// sessionless: auth type 0, session seq 0, session id 0
	b := []byte{0x20, 0x18, 0xc8, 0x81, netFn << 2, 0x00, cmd}
	b = append(b, data...)
	b[5] = checksum(b[1:5])
	b = append(b, checksum(b[4:]))
	outer := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	outer[0] = 0x00 // auth none
	return append(outer, b...)
}

func getChannelAuthCap() []byte {
	return rmcp(ipmiHdr(0x06, 0x38, []byte{0x0e, 0x04}))
}

func getSessionChallenge(user string) []byte {
	u := make([]byte, 16)
	copy(u, []byte(user))
	return rmcp(ipmiHdr(0x06, 0x39, append([]byte{0x00}, u...)))
}

func activateSession(sid uint32, challenge []byte, password string) []byte {
	pw := make([]byte, 16)
	copy(pw, []byte(password))
	auth := md5.Sum(append(append(pw, challenge...), pw...))
	data := []byte{0x02, 0x04}
	var sidb [4]byte
	binary.LittleEndian.PutUint32(sidb[:], sid)
	data = append(data, sidb[:]...)
	data = append(data, challenge...)
	data = append(data, 0x01, 0x00, 0x00, 0x00)
	_ = auth
	return rmcp(ipmiHdr(0x06, 0x3a, data))
}

func checksum(b []byte) byte {
	var s byte
	for _, x := range b {
		s += x
	}
	return -s
}

func send(conn net.Conn, b []byte) error {
	_, err := conn.Write(b)
	return err
}

func recv(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func extractIPMI(pkt []byte) []byte {
	idx := bytes.Index(pkt, []byte{0x06, 0x00, 0xff, 0x07})
	if idx < 0 {
		if len(pkt) > 4 {
			return pkt[4:]
		}
		return pkt
	}
	return pkt[idx+4:]
}
