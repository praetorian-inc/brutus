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
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// smbCapture is a minimal SMB2 server. It answers negotiate and the NTLM
// challenge, then records the domain field of any Type 3 authenticate message.
// TargetName in the challenge is always CORP, so a client that fills an empty
// domain from the challenge will be caught.
type smbCapture struct {
	ln         net.Listener
	computer   string
	mu         sync.Mutex
	domains    []string
	type3Count int
}

func startSMBCapture(t *testing.T, computer string) *smbCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &smbCapture{ln: ln, computer: computer}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smbCapture) addr() string { return s.ln.Addr().String() }

func (s *smbCapture) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *smbCapture) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		pkt, err := readSMB(conn)
		if err != nil {
			return
		}
		if len(pkt) < 64 {
			return
		}
		cmd := binary.LittleEndian.Uint16(pkt[12:14])
		msgID := binary.LittleEndian.Uint64(pkt[24:32])
		switch cmd {
		case smb2Negotiate:
			if err := writeSMB(conn, negotiateResponse(msgID)); err != nil {
				return
			}
		case smb2SessionSetup:
			if isType3(pkt) {
				domain, _ := winlocal.AuthenticateDomain(pkt)
				s.mu.Lock()
				s.domains = append(s.domains, domain)
				s.type3Count++
				s.mu.Unlock()
				return
			}
			token, err := wrapNegTokenResp(winlocal.ChallengeMessage("CORP", s.computer))
			if err != nil {
				return
			}
			if err := writeSMB(conn, sessionSetupResponse(msgID, token)); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *smbCapture) type3() (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.type3Count, append([]string(nil), s.domains...)
}

func isType3(pkt []byte) bool {
	i := strings.Index(string(pkt), "NTLMSSP\x00")
	if i < 0 || i+12 > len(pkt) {
		return false
	}
	return binary.LittleEndian.Uint32(pkt[i+8:i+12]) == 3
}

func negotiateResponse(msgID uint64) []byte {
	pkt := make([]byte, 64+64)
	copy(pkt[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[4:6], 64)
	binary.LittleEndian.PutUint16(pkt[12:14], smb2Negotiate)
	binary.LittleEndian.PutUint16(pkt[14:16], 1) // credit
	binary.LittleEndian.PutUint32(pkt[16:20], 1) // server to redir
	binary.LittleEndian.PutUint64(pkt[24:32], msgID)
	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 1)     // signing enabled, not required
	binary.LittleEndian.PutUint16(body[4:6], 0x210) // SMB 2.1
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	binary.LittleEndian.PutUint32(body[36:40], 65536)
	return pkt
}

func sessionSetupResponse(msgID uint64, token []byte) []byte {
	pkt := make([]byte, 64+8+len(token))
	copy(pkt[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[4:6], 64)
	binary.LittleEndian.PutUint32(pkt[8:12], statusMore)
	binary.LittleEndian.PutUint16(pkt[12:14], smb2SessionSetup)
	binary.LittleEndian.PutUint16(pkt[14:16], 1)
	binary.LittleEndian.PutUint32(pkt[16:20], 1)
	binary.LittleEndian.PutUint64(pkt[24:32], msgID)
	binary.LittleEndian.PutUint64(pkt[40:48], 1) // session id
	body := pkt[64:]
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], 72) // security buffer offset
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(token)))
	copy(pkt[64+8:], token)
	return pkt
}

func wrapNegTokenResp(token []byte) ([]byte, error) {
	// [1] EXPLICIT SEQUENCE { [0] ENUMERATED 1, [1] OID, [2] OCTET STRING token }.
	// go-smb2 decodes this with ber.UnmarshalWithParams(..., "explicit,tag:1").
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	body := append([]byte{0xa0, 0x03, 0x0a, 0x01, 0x01}, derTLV(0xa1, oid)...)
	body = append(body, derTLV(0xa2, derTLV(0x04, token))...)
	return derTLV(0xa1, derTLV(0x30, body)), nil
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

func TestUnqualifiedSMBUsesComputerNameNotDomain(t *testing.T) {
	s := startSMBCapture(t, "SERVER01")
	p := &Plugin{}

	done := make(chan *brutus.Result, 1)
	go func() {
		done <- p.Test(context.Background(), s.addr(), "Administrator", "password", 3*time.Second, brutus.PluginConfig{})
	}()

	n, domains := waitType3(t, s, done)
	require.Equal(t, 1, n)
	assert.Equal(t, []string{"SERVER01"}, domains, "unqualified name must be a local login, not CORP from the challenge")
}

func TestExplicitDomainSMBIsOptIn(t *testing.T) {
	s := startSMBCapture(t, "SERVER01")
	p := &Plugin{}

	done := make(chan *brutus.Result, 1)
	go func() {
		done <- p.Test(context.Background(), s.addr(), `CORP\Administrator`, "password", 3*time.Second, brutus.PluginConfig{})
	}()

	n, domains := waitType3(t, s, done)
	require.Equal(t, 1, n)
	assert.Equal(t, []string{"CORP"}, domains)
}

func TestMissingComputerNameDoesNotFallBackToDomain(t *testing.T) {
	s := startSMBCapture(t, "")
	p := &Plugin{}
	result := p.Test(context.Background(), s.addr(), "Administrator", "password", 3*time.Second, brutus.PluginConfig{})
	require.NotNil(t, result)
	assert.False(t, result.Success)
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	n, domains := s.type3()
	assert.Zero(t, n, "must not authenticate when the computer name is unknown; got domains %v", domains)
}

func TestDefaultSMBCredentialsAreLocal(t *testing.T) {
	for _, mode := range []brutus.Mode{brutus.ModeCautious, brutus.ModeDefault, brutus.ModeAggressive} {
		for _, c := range brutus.DefaultCredentialsForMode("smb", mode) {
			if strings.ContainsAny(c.Username, `\@`) {
				t.Errorf("mode %s default %q is not an unqualified local account", mode, c.Username)
			}
		}
	}
}

func TestProbeReadsComputerName(t *testing.T) {
	s := startSMBCapture(t, "SERVER01")
	name, err := probeComputer(context.Background(), s.addr(), 3*time.Second, "")
	require.NoError(t, err)
	assert.Equal(t, "SERVER01", name)
}

func waitType3(t *testing.T, s *smbCapture, done <-chan *brutus.Result) (int, []string) {
	t.Helper()
	deadline := time.After(4 * time.Second)
	for {
		if n, domains := s.type3(); n > 0 {
			return n, domains
		}
		select {
		case <-deadline:
			select {
			case result := <-done:
				t.Fatalf("no Type 3; Test error=%v", result.Error)
			default:
				t.Fatal("no Type 3")
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
}
