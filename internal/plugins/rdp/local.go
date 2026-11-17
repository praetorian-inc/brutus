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

package rdp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ntlmDomain is the domain field to give the CredSSP connector.
//
// Unqualified names are local SAM logins. An empty domain is not: NTLMv2
// salted with an empty domain does not authenticate locally, and Windows can
// pass the attempt through to a DC. The computer name comes from the NLA
// challenge and is never the challenge TargetName.
func ntlmDomain(ctx context.Context, addr, username string, timeout time.Duration, proxyURL, tlsMode string) (domain, user string, err error) {
	id := winlocal.Parse(username)
	if !id.Local {
		return id.Domain, id.User, nil
	}
	name, err := winlocal.Resolve(ctx, "rdp|"+addr, func(ctx context.Context) (string, error) {
		return probeComputer(ctx, addr, timeout, proxyURL, tlsMode)
	})
	if err != nil {
		return "", "", err
	}
	return name, id.User, nil
}

func probeComputer(ctx context.Context, addr string, timeout time.Duration, proxyURL, tlsMode string) (string, error) {
	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, proxyURL)
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

	if _, err := conn.Write(hybridNegReq()); err != nil {
		return "", err
	}
	frame, err := readRDPFrame(conn)
	if err != nil {
		return "", err
	}
	if !selectedHybrid(frame) {
		return "", fmt.Errorf("local auth: server did not select NLA")
	}

	host, _, _ := net.SplitHostPort(addr)
	tlsConn := tls.Client(conn, rdpTLSConfig(tlsMode, host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", err
	}

	req, err := tsRequest(winlocal.NegotiateMessage())
	if err != nil {
		return "", err
	}
	if _, err := tlsConn.Write(req); err != nil {
		return "", err
	}
	resp, err := readBER(tlsConn, 1<<16)
	if err != nil {
		return "", err
	}
	name, ok := winlocal.ComputerName(resp)
	if !ok {
		return "", fmt.Errorf("local auth: server did not advertise a computer name")
	}
	return name, nil
}

func hybridNegReq() []byte {
	req := buildNegReq()
	binary.LittleEndian.PutUint32(req[15:19], protocolHybrid)
	return req
}

func selectedHybrid(frame []byte) bool {
	if len(frame) < 19 || frame[0] != negTPKTVersion {
		return false
	}
	n := int(binary.BigEndian.Uint16(frame[2:4]))
	if n < 19 || n > len(frame) {
		return false
	}
	trailer := frame[n-8 : n]
	if trailer[0] != negRspType {
		return false
	}
	selected := binary.LittleEndian.Uint32(trailer[4:8])
	return selected&protocolHybrid != 0 || selected&protocolHybridEx != 0
}

// tsRequest is a CredSSP TSRequest version 3 carrying an NTLM negotiate token.
// Wire format is the BER element itself, which is what ironrdp writes.
func tsRequest(ntlm []byte) ([]byte, error) {
	token, err := spnegoInit(ntlm)
	if err != nil {
		return nil, err
	}
	octet := derTLV(0x04, token)
	item := derTLV(0x30, derTLV(0xa0, octet))
	nego := derTLV(0xa1, derTLV(0x30, item))
	version := []byte{0xa0, 0x03, 0x02, 0x01, 0x03}
	return derTLV(0x30, append(version, nego...)), nil
}

func spnegoInit(ntlm []byte) ([]byte, error) {
	oidSpnego := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLM := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	mechList := derTLV(0x30, oidNTLM)
	mechTypes := derTLV(0xa0, mechList)
	mechToken := derTLV(0xa2, derTLV(0x04, ntlm))
	inner := derTLV(0x30, append(mechTypes, mechToken...))
	body := append(append([]byte{}, oidSpnego...), derTLV(0xa0, inner)...)
	return derTLV(0x60, body), nil
}

func derTLV(tag byte, content []byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	default:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

func readBER(r io.Reader, max int) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, fmt.Errorf("local auth: expected CredSSP SEQUENCE, got 0x%02x", hdr[0])
	}
	var n int
	var extra []byte
	switch {
	case hdr[1] < 0x80:
		n = int(hdr[1])
	default:
		nb := int(hdr[1] & 0x7f)
		if nb == 0 || nb > 3 {
			return nil, fmt.Errorf("local auth: bad CredSSP length")
		}
		extra = make([]byte, nb)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, err
		}
		for _, b := range extra {
			n = n<<8 | int(b)
		}
	}
	if n < 0 || n > max {
		return nil, fmt.Errorf("local auth: CredSSP length %d", n)
	}
	content := make([]byte, n)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(extra)+n)
	out = append(out, hdr...)
	out = append(out, extra...)
	out = append(out, content...)
	return out, nil
}
