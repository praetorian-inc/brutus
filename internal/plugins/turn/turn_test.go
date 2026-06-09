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

package turn

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "turn", p.Name())
}

// =============================================================================
// Mock TURN Server
// =============================================================================

// mockTURNServer starts a UDP listener that runs a scripted TURN conversation.
func mockTURNServer(t *testing.T, handler func(pc net.PacketConn)) (addr string, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(pc)
	}()

	cleanup = func() {
		_ = pc.Close()
		<-done
	}
	return pc.LocalAddr().String(), cleanup
}

// stunRecv reads one STUN message from the PacketConn.
func stunRecv(pc net.PacketConn) ([]byte, net.Addr) {
	buf := make([]byte, maxMessageSize)
	n, addr, _ := pc.ReadFrom(buf)
	return buf[:n], addr
}

// stunSend writes a STUN message to the given address.
func stunSend(pc net.PacketConn, msg []byte, addr net.Addr) {
	_, _ = pc.WriteTo(msg, addr)
}

// extractTxID extracts the 12-byte transaction ID from a STUN message.
func extractTxID(msg []byte) [12]byte {
	var txID [12]byte
	if len(msg) >= stunHeaderSize {
		copy(txID[:], msg[8:20])
	}
	return txID
}

// buildMockErrorResponse builds a STUN error response for testing.
func buildMockErrorResponse(txID [12]byte, code int, realm, nonce string) []byte {
	class := byte(code / 100)
	number := byte(code % 100)
	errData := []byte{0, 0, class, number}

	var attrs []byte
	attrs = append(attrs, encodeAttr(attrErrorCode, errData)...)
	if realm != "" {
		attrs = append(attrs, encodeStringAttr(attrRealm, realm)...)
	}
	if nonce != "" {
		attrs = append(attrs, encodeStringAttr(attrNonce, nonce)...)
	}

	msg := make([]byte, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], msgAllocateError)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[stunHeaderSize:], attrs)
	return msg
}

// buildMockSuccessResponse builds a STUN success response for testing.
func buildMockSuccessResponse(txID [12]byte) []byte {
	msg := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(msg[0:2], msgAllocateSuccess)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	return msg
}

// =============================================================================
// Plugin Tests
// =============================================================================

func TestPlugin_Test_ValidCredentials(t *testing.T) {
	refreshReceived := make(chan struct{}, 1)

	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		// Receive unauthenticated Allocate.
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Send 401 challenge with realm and nonce.
		stunSend(pc, buildMockErrorResponse(txID, 401, "example.com", "testnonce"), client)

		// Receive authenticated Allocate.
		msg, client = stunRecv(pc)
		txID = extractTxID(msg)
		// Send success.
		stunSend(pc, buildMockSuccessResponse(txID), client)

		// Expect deallocation Refresh (LIFETIME=0).
		msg, _ = stunRecv(pc)
		if len(msg) >= stunHeaderSize {
			msgType := binary.BigEndian.Uint16(msg[0:2])
			if msgType == msgRefreshRequest {
				refreshReceived <- struct{}{}
			}
		}
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "password", 5*time.Second, brutus.PluginConfig{})

	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Equal(t, "turn", result.Protocol)
	assert.Equal(t, addr, result.Target)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, "password", result.Password)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))

	// Verify deallocation was sent.
	select {
	case <-refreshReceived:
		// OK — deallocation Refresh was received.
	case <-time.After(2 * time.Second):
		t.Error("expected Refresh(LIFETIME=0) deallocation after success")
	}
}

func TestPlugin_Test_InvalidCredentials(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		// Receive unauthenticated Allocate.
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Send 401 challenge.
		stunSend(pc, buildMockErrorResponse(txID, 401, "example.com", "testnonce"), client)

		// Receive authenticated Allocate.
		msg, client = stunRecv(pc)
		txID = extractTxID(msg)
		// Reject: bad credentials.
		stunSend(pc, buildMockErrorResponse(txID, 401, "", ""), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "wrong", 5*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.Nil(t, result.Error, "auth failure should return nil error")
	assert.Equal(t, "turn", result.Protocol)
}

func TestPlugin_Test_StaleNonce_RetrySucceeds(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		// Receive unauthenticated Allocate.
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Send 401 challenge.
		stunSend(pc, buildMockErrorResponse(txID, 401, "example.com", "oldnonce"), client)

		// Receive authenticated Allocate — respond with 438 Stale Nonce.
		msg, client = stunRecv(pc)
		txID = extractTxID(msg)
		stunSend(pc, buildMockErrorResponse(txID, 438, "example.com", "freshnonce"), client)

		// Receive retried Allocate with fresh nonce — accept.
		msg, client = stunRecv(pc)
		txID = extractTxID(msg)
		stunSend(pc, buildMockSuccessResponse(txID), client)

		// Consume deallocation Refresh.
		stunRecv(pc)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})

	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
}

func TestPlugin_Test_StaleNonce_ExhaustedRetries(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		// Receive unauthenticated Allocate.
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		stunSend(pc, buildMockErrorResponse(txID, 401, "example.com", "nonce0"), client)

		// Keep returning 438 for every retry.
		for i := 0; i <= maxStaleRetries; i++ {
			msg, client = stunRecv(pc)
			txID = extractTxID(msg)
			stunSend(pc, buildMockErrorResponse(txID, 438, "example.com", fmt.Sprintf("nonce%d", i+1)), client)
		}
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
	assert.Contains(t, result.Error.Error(), "stale nonce persisted")
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (will timeout).
	result := p.Test(ctx, "198.51.100.1:3478", "admin", "pass", 500*time.Millisecond, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_UnauthSuccess_DuringTest(t *testing.T) {
	// Server responds with success to the unauthenticated request (open relay).
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		stunSend(pc, buildMockSuccessResponse(txID), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})

	assert.True(t, result.Success)
	assert.Nil(t, result.Error)
	assert.Contains(t, result.Banner, "unauthenticated")
}

func TestPlugin_Test_NonSTUNResponse(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		_, client := stunRecv(pc)
		// Send garbage (not a STUN message).
		stunSend(pc, []byte("HTTP/1.1 200 OK\r\n"), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_MissingRealmOrNonce(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Send 401 without realm or nonce.
		stunSend(pc, buildMockErrorResponse(txID, 401, "", ""), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.Test(context.Background(), addr, "admin", "pass", 5*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "missing realm or nonce")
}

// =============================================================================
// UnauthChecker Tests
// =============================================================================

func TestPlugin_CheckUnauth_OpenRelay(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Accept allocation without credentials.
		stunSend(pc, buildMockSuccessResponse(txID), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.CheckUnauth(context.Background(), addr, 5*time.Second, brutus.PluginConfig{})

	assert.True(t, result.Success)
	assert.Contains(t, result.Banner, "[CRITICAL]")
	assert.Contains(t, result.Banner, "unauthenticated")
}

func TestPlugin_CheckUnauth_Secure(t *testing.T) {
	addr, cleanup := mockTURNServer(t, func(pc net.PacketConn) {
		msg, client := stunRecv(pc)
		txID := extractTxID(msg)
		// Properly require auth.
		stunSend(pc, buildMockErrorResponse(txID, 401, "example.com", "nonce123"), client)
	})
	defer cleanup()

	p := &Plugin{}
	result := p.CheckUnauth(context.Background(), addr, 5*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success)
	assert.Empty(t, result.Banner)
}

func TestPlugin_CheckUnauth_Unreachable(t *testing.T) {
	p := &Plugin{}
	result := p.CheckUnauth(context.Background(), "198.51.100.1:3478", 500*time.Millisecond, brutus.PluginConfig{})

	assert.False(t, result.Success)
}

// =============================================================================
// STUN Encoding/Parsing Unit Tests
// =============================================================================

func TestBuildAllocateRequest(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg := buildAllocateRequest(txID)

	// Verify header.
	assert.Equal(t, uint16(msgAllocateRequest), binary.BigEndian.Uint16(msg[0:2]))
	assert.Equal(t, uint32(magicCookie), binary.BigEndian.Uint32(msg[4:8]))
	assert.Equal(t, txID[:], msg[8:20])

	// Parse and verify attributes.
	_, attrs, err := parseSTUNMessage(msg)
	require.NoError(t, err)
	require.Contains(t, attrs, uint16(attrRequestedTransport))
	assert.Equal(t, byte(protoUDP), attrs[attrRequestedTransport][0])
}

func TestParseSTUNMessage_Valid(t *testing.T) {
	txID := [12]byte{0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0}
	resp := buildMockErrorResponse(txID, 401, "myrealm", "mynonce")

	msgType, attrs, err := parseSTUNMessage(resp)
	require.NoError(t, err)
	assert.Equal(t, uint16(msgAllocateError), msgType)
	assert.Equal(t, 401, getErrorCode(attrs))
	assert.Equal(t, "myrealm", getStringAttr(attrs, attrRealm))
	assert.Equal(t, "mynonce", getStringAttr(attrs, attrNonce))
}

func TestParseSTUNMessage_TooShort(t *testing.T) {
	_, _, err := parseSTUNMessage([]byte{0, 0, 0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseSTUNMessage_BadCookie(t *testing.T) {
	msg := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint32(msg[4:8], 0xDEADBEEF)
	_, _, err := parseSTUNMessage(msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "magic cookie")
}

func TestParseSTUNMessage_Truncated(t *testing.T) {
	msg := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(msg[2:4], 100) // claims 100 bytes of attrs
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	_, _, err := parseSTUNMessage(msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{"unauthorized", 401},
		{"stale nonce", 438},
		{"forbidden", 403},
		{"quota reached", 486},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class := byte(tt.code / 100)
			number := byte(tt.code % 100)
			attrs := map[uint16][]byte{
				attrErrorCode: {0, 0, class, number},
			}
			assert.Equal(t, tt.code, getErrorCode(attrs))
		})
	}
}

func TestGetErrorCode_Missing(t *testing.T) {
	assert.Equal(t, 0, getErrorCode(map[uint16][]byte{}))
}

func TestGetStringAttr_Missing(t *testing.T) {
	assert.Equal(t, "", getStringAttr(map[uint16][]byte{}, attrRealm))
}

func TestLongTermKey(t *testing.T) {
	// RFC 5389 long-term key = MD5("user:realm:pass").
	key := longTermKey("user", "realm", "pass")
	assert.Len(t, key, 16, "MD5 key should be 16 bytes")
}

func TestEncodeAttr_Padding(t *testing.T) {
	// 3-byte value should be padded to 4 bytes.
	attr := encodeAttr(0x0006, []byte("abc"))
	assert.Len(t, attr, 8) // 4 header + 3 value + 1 padding

	// Length field should be 3 (actual length, not padded).
	assert.Equal(t, uint16(3), binary.BigEndian.Uint16(attr[2:4]))

	// 4-byte value needs no padding.
	attr = encodeAttr(0x0006, []byte("abcd"))
	assert.Len(t, attr, 8) // 4 header + 4 value
}

func TestBuildAuthenticatedAllocateRequest(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg := buildAuthenticatedAllocateRequest(txID, "user", "realm", "nonce", "pass")

	// Should parse without error.
	msgType, attrs, err := parseSTUNMessage(msg)
	require.NoError(t, err)
	assert.Equal(t, uint16(msgAllocateRequest), msgType)

	// Should contain expected attributes.
	assert.Contains(t, attrs, uint16(attrRequestedTransport))
	assert.Contains(t, attrs, uint16(attrUsername))
	assert.Contains(t, attrs, uint16(attrRealm))
	assert.Contains(t, attrs, uint16(attrNonce))
	assert.Contains(t, attrs, uint16(attrMessageIntegrity))

	// Verify attribute values.
	assert.Equal(t, "user", string(attrs[attrUsername]))
	assert.Equal(t, "realm", string(attrs[attrRealm]))
	assert.Equal(t, "nonce", string(attrs[attrNonce]))
	assert.Len(t, attrs[attrMessageIntegrity], 20, "HMAC-SHA1 should be 20 bytes")
}

func TestBuildRefreshRequest(t *testing.T) {
	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg := buildRefreshRequest(txID, "user", "realm", "nonce", "pass", 0)

	msgType, attrs, err := parseSTUNMessage(msg)
	require.NoError(t, err)
	assert.Equal(t, uint16(msgRefreshRequest), msgType)

	// Should contain LIFETIME=0.
	require.Contains(t, attrs, uint16(attrLifetime))
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(attrs[attrLifetime]))

	// Should contain auth attributes and MESSAGE-INTEGRITY.
	assert.Contains(t, attrs, uint16(attrUsername))
	assert.Contains(t, attrs, uint16(attrRealm))
	assert.Contains(t, attrs, uint16(attrNonce))
	assert.Contains(t, attrs, uint16(attrMessageIntegrity))
	assert.Len(t, attrs[attrMessageIntegrity], 20)
}
