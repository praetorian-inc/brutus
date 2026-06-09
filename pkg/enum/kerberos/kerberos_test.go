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

package kerberos

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKDC simulates a Kerberos Key Distribution Center for testing.
// It listens on a random TCP port, parses incoming AS-REQ messages,
// and returns KRB-ERROR responses based on a configurable user map.
type mockKDC struct {
	listener net.Listener
	users    map[string]bool // username -> exists (responds with PREAUTH_REQUIRED)
	wg       sync.WaitGroup
	done     chan struct{}
}

// newMockKDC starts a mock KDC on a random local port.
func newMockKDC(t *testing.T, users map[string]bool) *mockKDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to start mock KDC")
	m := &mockKDC{listener: ln, users: users, done: make(chan struct{})}
	m.wg.Add(1)
	go m.serve()
	return m
}

func (m *mockKDC) Addr() string { return m.listener.Addr().String() }

func (m *mockKDC) Close() {
	close(m.done)
	_ = m.listener.Close()
	m.wg.Wait()
}

func (m *mockKDC) serve() {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				continue
			}
		}
		m.wg.Add(1)
		go m.handleConn(conn)
	}
}

func (m *mockKDC) handleConn(conn net.Conn) {
	defer m.wg.Done()
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > 1024*1024 {
		return
	}
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	var asReq messages.ASReq
	if err := asReq.Unmarshal(body); err != nil {
		return
	}

	username := ""
	if len(asReq.ReqBody.CName.NameString) > 0 {
		username = asReq.ReqBody.CName.NameString[0]
	}
	realm := asReq.ReqBody.Realm

	var code int32
	if m.users[username] {
		code = errorcode.KDC_ERR_PREAUTH_REQUIRED
	} else {
		code = errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
	}

	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	krbErr := messages.NewKRBError(sname, realm, code, "")
	respBytes, err := krbErr.Marshal()
	if err != nil {
		return
	}

	respLen := make([]byte, 4)
	binary.BigEndian.PutUint32(respLen, uint32(len(respBytes)))
	_, _ = conn.Write(respLen)
	_, _ = conn.Write(respBytes)
}

func TestEnumUser_ExistingUser(t *testing.T) {
	t.Parallel()
	kdc := newMockKDC(t, map[string]bool{"administrator": true})
	t.Cleanup(kdc.Close)

	result := EnumUser(context.Background(), kdc.Addr(), "TEST.LOCAL", "administrator", 5*time.Second)

	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "user should exist")
	assert.False(t, result.NoPreAuth, "user should require preauth")
	assert.Equal(t, "administrator", result.Username)
	assert.Equal(t, "TEST.LOCAL", result.Realm)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestEnumUser_NonExistentUser(t *testing.T) {
	t.Parallel()
	kdc := newMockKDC(t, map[string]bool{"administrator": true})
	t.Cleanup(kdc.Close)

	result := EnumUser(context.Background(), kdc.Addr(), "TEST.LOCAL", "doesnotexist", 5*time.Second)

	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "user should not exist")
	assert.False(t, result.NoPreAuth)
}

func TestEnumUser_MultipleUsers(t *testing.T) {
	t.Parallel()
	users := map[string]bool{"admin": true, "guest": true, "krbtgt": true}
	kdc := newMockKDC(t, users)
	t.Cleanup(kdc.Close)

	tests := []struct {
		name     string
		username string
		exists   bool
	}{
		{"admin exists", "admin", true},
		{"guest exists", "guest", true},
		{"krbtgt exists", "krbtgt", true},
		{"fake not found", "fake", false},
		{"nonexistent not found", "nonexistent", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := EnumUser(context.Background(), kdc.Addr(), "TEST.LOCAL", tt.username, 5*time.Second)
			require.NoError(t, result.Error)
			assert.Equal(t, tt.exists, result.Exists, "user %q", tt.username)
		})
	}
}

func TestEnumUser_ConnectionRefused(t *testing.T) {
	t.Parallel()
	result := EnumUser(context.Background(), "127.0.0.1:1", "TEST.LOCAL", "admin", 2*time.Second)
	assert.Error(t, result.Error)
	assert.False(t, result.Exists)
}

func TestEnumUser_Timeout(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	start := time.Now()
	result := EnumUser(context.Background(), ln.Addr().String(), "TEST.LOCAL", "admin", 500*time.Millisecond)
	elapsed := time.Since(start)

	assert.Error(t, result.Error)
	assert.Less(t, elapsed, 3*time.Second)
}

func TestEnumUser_ContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := EnumUser(ctx, "127.0.0.1:88", "TEST.LOCAL", "admin", 5*time.Second)
	assert.Error(t, result.Error)
}

func TestBuildASReq(t *testing.T) {
	t.Parallel()
	data, err := buildASReq("testuser", "test.local")
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var asReq messages.ASReq
	require.NoError(t, asReq.Unmarshal(data))

	assert.Equal(t, "testuser", asReq.ReqBody.CName.NameString[0])
	assert.Equal(t, "TEST.LOCAL", asReq.ReqBody.Realm)
	assert.Len(t, asReq.ReqBody.EType, 3)
	assert.Empty(t, asReq.PAData, "PAData should be empty")
}

func TestBuildASReq_RealmUppercased(t *testing.T) {
	t.Parallel()
	data, err := buildASReq("user", "corp.local")
	require.NoError(t, err)
	var asReq messages.ASReq
	require.NoError(t, asReq.Unmarshal(data))
	assert.Equal(t, "CORP.LOCAL", asReq.ReqBody.Realm)
}

func TestSendKerberosTCP(t *testing.T) {
	t.Parallel()
	expected := []byte("mock-kerberos-response")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		lenBuf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, lenBuf); readErr != nil {
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf)
		buf := make([]byte, msgLen)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			return
		}
		respLen := make([]byte, 4)
		binary.BigEndian.PutUint32(respLen, uint32(len(expected)))
		_, _ = conn.Write(respLen)
		_, _ = conn.Write(expected)
	}()

	resp, err := sendKerberosTCP(context.Background(), ln.Addr().String(), []byte("test-request"), 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, expected, resp)
}

func TestSendKerberosTCP_DefaultPort(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := sendKerberosTCP(ctx, "127.0.0.1", []byte("test"), 500*time.Millisecond)
	assert.Error(t, err)
}

// TODO: Add TestEnumUser_NoPreAuth when a valid AS-REP can be constructed.
