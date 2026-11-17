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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestProbeReadsRDPComputerName(t *testing.T) {
	ln := startRDPCapture(t, "SERVER01")
	name, err := probeComputer(context.Background(), ln.Addr().String(), 3*time.Second, "", "")
	require.NoError(t, err)
	assert.Equal(t, "SERVER01", name)
}

func TestRDPMissingComputerNameDoesNotAuth(t *testing.T) {
	ln := startRDPCapture(t, "")
	p := &Plugin{}
	result := p.Test(context.Background(), ln.Addr().String(), "Administrator", "password", 3*time.Second, brutus.PluginConfig{})
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "computer name")
	assert.False(t, result.Success)
}

func TestExplicitRDPDomainSkipsProbe(t *testing.T) {
	domain, user, err := ntlmDomain(context.Background(), "127.0.0.1:1", `CORP\Administrator`, time.Second, "", "")
	require.NoError(t, err)
	assert.Equal(t, "CORP", domain)
	assert.Equal(t, "Administrator", user)
}

func TestDefaultRDPCredentialsAreLocal(t *testing.T) {
	for _, mode := range []brutus.Mode{brutus.ModeCautious, brutus.ModeDefault, brutus.ModeAggressive} {
		for _, c := range brutus.DefaultCredentialsForMode("rdp", mode) {
			if strings.ContainsAny(c.Username, `\@`) {
				t.Errorf("mode %s default %q is not an unqualified local account", mode, c.Username)
			}
		}
	}
}

func startRDPCapture(t *testing.T, computer string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	cert := testCert(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRDPCapture(conn, cert, computer)
		}
	}()
	return ln
}

func serveRDPCapture(conn net.Conn, cert tls.Certificate, computer string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	frame, err := readRDPFrame(conn)
	if err != nil || len(frame) < 19 {
		return
	}
	rsp := make([]byte, 19)
	copy(rsp, frame[:11])
	rsp[5] = 0xD0 // Connection Confirm
	rsp[11] = negRspType
	binaryPut16(rsp[13:15], 8)
	binaryPut32(rsp[15:19], protocolHybrid)
	if _, err := conn.Write(rsp); err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	if _, err := readBER(tlsConn, 1<<16); err != nil {
		return
	}
	chal := winlocal.ChallengeMessage("CORP", computer)
	_, _ = tlsConn.Write(derTLV(0x30, chal))
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func binaryPut16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func binaryPut32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
