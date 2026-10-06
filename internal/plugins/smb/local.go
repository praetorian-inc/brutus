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

package smb

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	smb2Negotiate    = 0
	smb2SessionSetup = 1
	statusSuccess    = 0
	statusMore       = 0xC0000016

	dialect202 = 0x0202
	dialect210 = 0x0210
	dialect300 = 0x0300
	dialect302 = 0x0302
	dialect311 = 0x0311
)

// ntlmDomain is the domain field to put on the wire.
//
// Unqualified names are local: the domain is the target computer name from
// MsvAvNbComputerName. An empty domain is not local. go-smb2 substitutes the
// challenge TargetName, which is the AD domain on a member, and that spray
// locks the domain account.
func ntlmDomain(ctx context.Context, addr, username string, timeout time.Duration, proxyURL string) (domain, user string, err error) {
	id := winlocal.Parse(username)
	if !id.Local {
		return id.Domain, id.User, nil
	}
	name, err := winlocal.Resolve(ctx, "smb|"+addr, func(ctx context.Context) (string, error) {
		return probeComputer(ctx, addr, timeout, proxyURL)
	})
	if err != nil {
		return "", "", err
	}
	return name, id.User, nil
}

func probeComputer(ctx context.Context, addr string, timeout time.Duration, proxyURL string) (string, error) {
	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, proxyURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if err := setProbeDeadline(ctx, conn, timeout); err != nil {
		return "", err
	}

	if err := writeSMB(conn, negotiateRequest()); err != nil {
		return "", err
	}
	if _, err := readSMB(conn); err != nil {
		return "", err
	}

	token, err := wrapNegTokenInit(winlocal.NegotiateMessage())
	if err != nil {
		return "", err
	}
	if err := writeSMB(conn, sessionSetupRequest(token)); err != nil {
		return "", err
	}
	pkt, err := readSMB(conn)
	if err != nil {
		return "", err
	}
	status := binary.LittleEndian.Uint32(pkt[8:12])
	if status != statusSuccess && status != statusMore {
		return "", fmt.Errorf("local auth: session setup status 0x%08x", status)
	}
	name, ok := winlocal.ComputerName(pkt)
	if !ok {
		return "", fmt.Errorf("local auth: server did not advertise a computer name")
	}
	return name, nil
}

func setProbeDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return conn.SetDeadline(deadline)
}

func writeSMB(conn net.Conn, pkt []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(pkt)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(pkt)
	return err
}

func readSMB(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, fmt.Errorf("local auth: invalid SMB transport header")
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 64 || n > 1<<20 {
		return nil, fmt.Errorf("local auth: invalid SMB frame length %d", n)
	}
	pkt := make([]byte, n)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func negotiateRequest() []byte {
	dialects := []uint16{dialect311, dialect302, dialect300, dialect210, dialect202}
	// Body: 36-byte fixed + dialects, then 8-byte-aligned negotiate contexts.
	bodyFixed := 36 + len(dialects)*2
	ctxOff := (bodyFixed + 7) &^ 7
	preauth := preauthContext()
	enc := encryptionContext()
	// Pad the preauth context out to 8 bytes before the next context.
	preauthPad := (len(preauth) + 7) &^ 7
	bodyLen := ctxOff + preauthPad + len(enc)
	pkt := make([]byte, 64+bodyLen)

	putHeader(pkt, smb2Negotiate, 0, 1)
	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 1) // signing enabled
	binary.LittleEndian.PutUint32(body[8:12], 0x40)
	_, _ = rand.Read(body[12:28])
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+2*i:], d)
	}
	binary.LittleEndian.PutUint32(body[28:32], uint32(64+ctxOff)) // NegotiateContextOffset
	binary.LittleEndian.PutUint16(body[32:34], 2)                 // NegotiateContextCount
	copy(body[ctxOff:], preauth)
	copy(body[ctxOff+preauthPad:], enc)
	return pkt
}

func preauthContext() []byte {
	// 8-byte header + count(2) + saltLen(2) + alg(2) + salt(32) = 46.
	const saltLen = 32
	b := make([]byte, 8+4+2+saltLen)
	binary.LittleEndian.PutUint16(b[0:2], 1) // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
	binary.LittleEndian.PutUint16(b[2:4], 4+2+saltLen)
	binary.LittleEndian.PutUint16(b[8:10], 1) // algorithm count
	binary.LittleEndian.PutUint16(b[10:12], saltLen)
	binary.LittleEndian.PutUint16(b[12:14], 1) // SHA-512
	_, _ = rand.Read(b[14:])
	return b
}

func encryptionContext() []byte {
	b := make([]byte, 8+2+2)
	binary.LittleEndian.PutUint16(b[0:2], 2) // SMB2_ENCRYPTION_CAPABILITIES
	binary.LittleEndian.PutUint16(b[2:4], 4)
	binary.LittleEndian.PutUint16(b[8:10], 1)  // cipher count
	binary.LittleEndian.PutUint16(b[10:12], 2) // AES-128-GCM
	return b
}

func sessionSetupRequest(token []byte) []byte {
	pkt := make([]byte, 64+24+len(token))
	putHeader(pkt, smb2SessionSetup, 1, 1)
	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:2], 25)
	body[3] = 1 // signing enabled
	binary.LittleEndian.PutUint16(body[12:14], 64+24)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(token)))
	copy(body[24:], token)
	return pkt
}

func putHeader(pkt []byte, command uint16, msgID uint64, credit uint16) {
	copy(pkt[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[4:6], 64)
	binary.LittleEndian.PutUint16(pkt[6:8], 1) // credit charge
	binary.LittleEndian.PutUint16(pkt[12:14], command)
	binary.LittleEndian.PutUint16(pkt[14:16], credit)
	binary.LittleEndian.PutUint64(pkt[24:32], msgID)
}

var (
	spnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	ntlmOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

// Matches go-smb2's NegTokenInit, including the application tag rewrite Windows
// already accepts from that library.
type initialContextToken struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     []negTokenInit        `asn1:"optional,explict,tag:0"`
}

type negTokenInit struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	MechToken []byte                  `asn1:"explicit,optional,tag:2"`
}

func wrapNegTokenInit(ntlm []byte) ([]byte, error) {
	bs, err := asn1.Marshal(initialContextToken{
		ThisMech: spnegoOID,
		Init: []negTokenInit{{
			MechTypes: []asn1.ObjectIdentifier{ntlmOID},
			MechToken: ntlm,
		}},
	})
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, fmt.Errorf("local auth: empty SPNEGO token")
	}
	bs[0] = 0x60
	return bs, nil
}
