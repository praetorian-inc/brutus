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

package winrm

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/internal/winlocal"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// httpCapture speaks just enough HTTP NTLM for the WinRM client and the probe.
// The challenge TargetName is CORP. A client that leaves the domain empty, or
// fills it from TargetName, is caught by the recorded Type 3 domain.
type httpCapture struct {
	ln         net.Listener
	computer   string
	mu         sync.Mutex
	domains    []string
	type3Count int
}

func startHTTPCapture(t *testing.T, computer string) *httpCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &httpCapture{ln: ln, computer: computer}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *httpCapture) addr() string { return s.ln.Addr().String() }

func (s *httpCapture) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *httpCapture) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	for {
		req, err := readHTTP(br)
		if err != nil {
			return
		}
		token := authToken(req.header)
		switch {
		case isNTLMType(token, 3):
			domain, _ := winlocal.AuthenticateDomain(token)
			s.mu.Lock()
			s.domains = append(s.domains, domain)
			s.type3Count++
			s.mu.Unlock()
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		case isNTLMType(token, 1):
			raw := winlocal.ChallengeMessage("CORP", s.computer)
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate "+base64.StdEncoding.EncodeToString(raw)+"\r\nContent-Length: 0\r\n\r\n")
		default:
			_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n")
		}
	}
}

func (s *httpCapture) type3() (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.type3Count, append([]string(nil), s.domains...)
}

type httpReq struct {
	header textproto.MIMEHeader
}

func readHTTP(br *bufio.Reader) (httpReq, error) {
	if _, err := br.ReadString('\n'); err != nil {
		return httpReq{}, err
	}
	tp := textproto.NewReader(br)
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return httpReq{}, err
	}
	if n, err := strconv.Atoi(hdr.Get("Content-Length")); err == nil && n > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
			return httpReq{}, err
		}
	}
	return httpReq{header: hdr}, nil
}

func authToken(hdr textproto.MIMEHeader) []byte {
	v := hdr.Get("Authorization")
	scheme, rest, ok := strings.Cut(v, " ")
	if !ok || (!strings.EqualFold(scheme, "Negotiate") && !strings.EqualFold(scheme, "NTLM")) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return nil
	}
	return raw
}

func isNTLMType(token []byte, typ uint32) bool {
	i := strings.Index(string(token), "NTLMSSP\x00")
	if i < 0 || i+12 > len(token) {
		return false
	}
	return uint32(token[i+8]) == typ && token[i+9] == 0 && token[i+10] == 0 && token[i+11] == 0
}

func TestUnqualifiedWinRMUsesComputerNameNotDomain(t *testing.T) {
	s := startHTTPCapture(t, "SERVER01")
	p := &Plugin{}
	done := make(chan *brutus.Result, 1)
	go func() {
		done <- p.Test(context.Background(), s.addr(), "Administrator", "password", 3*time.Second, brutus.PluginConfig{})
	}()
	n, domains := waitWinRMType3(t, s, done)
	require.Equal(t, 1, n)
	assert.Equal(t, []string{"SERVER01"}, domains)
}

func TestExplicitDomainWinRMIsOptIn(t *testing.T) {
	s := startHTTPCapture(t, "SERVER01")
	p := &Plugin{}
	done := make(chan *brutus.Result, 1)
	go func() {
		done <- p.Test(context.Background(), s.addr(), `CORP\Administrator`, "password", 3*time.Second, brutus.PluginConfig{})
	}()
	n, domains := waitWinRMType3(t, s, done)
	require.Equal(t, 1, n)
	assert.Equal(t, []string{"CORP"}, domains)
}

func TestMissingWinRMComputerNameDoesNotFallBack(t *testing.T) {
	s := startHTTPCapture(t, "")
	p := &Plugin{}
	result := p.Test(context.Background(), s.addr(), "Administrator", "password", 3*time.Second, brutus.PluginConfig{})
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	n, domains := s.type3()
	assert.Zero(t, n, "must not authenticate without a computer name; got %v", domains)
}

func waitWinRMType3(t *testing.T, s *httpCapture, done <-chan *brutus.Result) (int, []string) {
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
