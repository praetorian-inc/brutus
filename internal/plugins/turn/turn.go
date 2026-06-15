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
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// STUN/TURN protocol constants (RFC 5389, RFC 5766).
const (
	stunHeaderSize = 20
	magicCookie    = 0x2112A442

	// STUN message types (method | class).
	msgAllocateRequest = 0x0003 // Allocate method, Request class
	msgAllocateSuccess = 0x0103 // Allocate method, Success Response class
	msgAllocateError   = 0x0113 // Allocate method, Error Response class

	// STUN message types — Refresh method.
	msgRefreshRequest = 0x0004 // Refresh method, Request class

	// STUN attribute types.
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrLifetime           = 0x000D
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrRequestedTransport = 0x0019

	// TURN error codes.
	codeUnauthorized = 401
	codeStaleNonce   = 438
	codeQuotaReached = 486

	// IANA protocol number for UDP.
	protoUDP = 17

	// Maximum STUN message size for UDP.
	maxMessageSize = 1500

	// maxStaleRetries is the number of times to retry on 438 Stale Nonce
	// before giving up. Nonces are connection-scoped and time-limited;
	// a retry with the fresh nonce from the 438 response usually succeeds.
	maxStaleRetries = 3
)

func init() {
	brutus.Register("turn", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements TURN credential testing via the STUN long-term
// credential mechanism (RFC 5389 Section 10.2, RFC 5766).
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "turn"
}

// Test attempts TURN authentication by sending an Allocate request and
// validating credentials via the long-term credential mechanism.
//
// Returns Result with:
//   - Success=true, Error=nil: Valid credentials (Allocate succeeded)
//   - Success=false, Error=nil: Invalid credentials (401 after auth attempt)
//   - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("turn", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "3478")
	addr := net.JoinHostPort(host, port)

	conn, err := brutus.DialWithProxy(ctx, "udp", addr, timeout, pluginCfg.ProxyURL)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: Send unauthenticated Allocate to obtain realm and nonce.
	txID := newTransactionID()
	if _, err = conn.Write(buildAllocateRequest(txID)); err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	buf := make([]byte, maxMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	msgType, respTxID, attrs, err := parseSTUNMessage(buf[:n])
	if err != nil {
		result.Error = brutus.WrapConnError(err)
		return result
	}

	if respTxID != txID {
		result.Error = fmt.Errorf("connection error: transaction ID mismatch in initial response")
		return result
	}

	// Unexpected success without credentials means open relay.
	if msgType == msgAllocateSuccess {
		result.Success = true
		result.Banner = "[CRITICAL] TURN server accepts unauthenticated allocations"
		deallocateUnauth(conn)
		return result
	}

	if msgType != msgAllocateError {
		result.Error = fmt.Errorf("connection error: unexpected STUN response type 0x%04x", msgType)
		return result
	}

	if getErrorCode(attrs) != codeUnauthorized {
		result.Error = fmt.Errorf("connection error: expected 401 challenge, got %d", getErrorCode(attrs))
		return result
	}

	realm := getStringAttr(attrs, attrRealm)
	nonce := getStringAttr(attrs, attrNonce)
	if realm == "" || nonce == "" {
		result.Error = fmt.Errorf("connection error: 401 response missing realm or nonce")
		return result
	}

	// Step 2: Send authenticated Allocate with MESSAGE-INTEGRITY.
	// Retry on 438 Stale Nonce with the fresh nonce from the response.
	for retry := 0; retry <= maxStaleRetries; retry++ {
		txID2 := newTransactionID()
		authReq := buildAuthenticatedAllocateRequest(txID2, username, realm, nonce, password)
		if _, err = conn.Write(authReq); err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}

		n, err = conn.Read(buf)
		if err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}

		msgType, respTxID, attrs, err = parseSTUNMessage(buf[:n])
		if err != nil {
			result.Error = brutus.WrapConnError(err)
			return result
		}

		if respTxID != txID2 {
			result.Error = fmt.Errorf("connection error: transaction ID mismatch in auth response")
			return result
		}

		switch msgType {
		case msgAllocateSuccess:
			result.Success = true
			// Release the allocation to avoid hitting per-user quota limits.
			deallocate(conn, username, realm, nonce, password)
			return result
		case msgAllocateError:
			switch getErrorCode(attrs) {
			case codeUnauthorized:
				// Invalid credentials -- auth failure.
				result.Error = nil
				return result
			case codeStaleNonce:
				// Nonce expired -- extract fresh nonce and retry.
				if fresh := getStringAttr(attrs, attrNonce); fresh != "" {
					nonce = fresh
				}
				continue
			case codeQuotaReached:
				// 486 = creds were valid but allocation quota exceeded.
				result.Success = true
				result.Banner = "valid credentials (allocation quota reached)"
				return result
			default:
				result.Error = fmt.Errorf("connection error: TURN error %d", getErrorCode(attrs))
				return result
			}
		default:
			result.Error = fmt.Errorf("connection error: unexpected response type 0x%04x", msgType)
			return result
		}
	}

	// Exhausted stale-nonce retries.
	result.Error = fmt.Errorf("connection error: stale nonce persisted after %d retries", maxStaleRetries)
	return result
}

// CheckUnauth probes for TURN servers that accept unauthenticated Allocate
// requests, indicating an open relay misconfiguration.
func (p *Plugin) CheckUnauth(ctx context.Context, target string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	result := brutus.NewResult("turn", target, "(unauthenticated)", "")
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	host, port := brutus.ParseTarget(target, "3478")
	addr := net.JoinHostPort(host, port)

	conn, err := brutus.DialWithProxy(ctx, "udp", addr, timeout, pluginCfg.ProxyURL)
	if err != nil {
		return result
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	txID := newTransactionID()
	if _, err = conn.Write(buildAllocateRequest(txID)); err != nil {
		return result
	}

	buf := make([]byte, maxMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		return result
	}

	msgType, respTxID, _, err := parseSTUNMessage(buf[:n])
	if err != nil {
		return result
	}

	if respTxID != txID {
		return result
	}

	if msgType == msgAllocateSuccess {
		result.Success = true
		result.Banner = "[CRITICAL] TURN server accepts unauthenticated allocations"
		deallocateUnauth(conn)
	}

	return result
}

// =============================================================================
// STUN Message Building
// =============================================================================

// deallocate sends an authenticated Refresh request with LIFETIME=0 to release
// a successful TURN allocation. This prevents per-user quota exhaustion during
// brute force. Errors are ignored (fire-and-forget before connection close).
func deallocate(conn net.Conn, username, realm, nonce, password string) {
	txID := newTransactionID()
	_, _ = conn.Write(buildRefreshRequest(txID, username, realm, nonce, password, 0))
}

// deallocateUnauth sends an unauthenticated Refresh request with LIFETIME=0
// to release an open-relay allocation (no credentials needed).
func deallocateUnauth(conn net.Conn) {
	txID := newTransactionID()
	_, _ = conn.Write(buildUnauthRefreshRequest(txID, 0))
}

// buildUnauthRefreshRequest builds an unauthenticated TURN Refresh request.
// Used to release open-relay allocations that were granted without credentials.
func buildUnauthRefreshRequest(txID [12]byte, lifetime uint32) []byte {
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, lifetime)
	attrs := encodeAttr(attrLifetime, lt)

	msg := make([]byte, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], msgRefreshRequest)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[stunHeaderSize:], attrs)
	return msg
}

// buildRefreshRequest builds an authenticated TURN Refresh request.
// Setting lifetime to 0 requests immediate deallocation.
func buildRefreshRequest(txID [12]byte, username, realm, nonce, password string, lifetime uint32) []byte {
	var attrs []byte
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, lifetime)
	attrs = append(attrs, encodeAttr(attrLifetime, lt)...)
	attrs = append(attrs, encodeStringAttr(attrUsername, username)...)
	attrs = append(attrs, encodeStringAttr(attrRealm, realm)...)
	attrs = append(attrs, encodeStringAttr(attrNonce, nonce)...)

	return buildAuthenticatedMessage(msgRefreshRequest, txID, attrs, username, realm, password)
}

// buildAllocateRequest builds an unauthenticated TURN Allocate request.
// Contains only the REQUESTED-TRANSPORT attribute (UDP).
func buildAllocateRequest(txID [12]byte) []byte {
	transport := []byte{protoUDP, 0, 0, 0} // protocol + 3 bytes RFFU
	attrs := encodeAttr(attrRequestedTransport, transport)

	msg := make([]byte, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], msgAllocateRequest)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[stunHeaderSize:], attrs)
	return msg
}

// buildAuthenticatedAllocateRequest builds an Allocate request with
// long-term credential MESSAGE-INTEGRITY (RFC 5389 Section 15.4).
func buildAuthenticatedAllocateRequest(txID [12]byte, username, realm, nonce, password string) []byte {
	// Build attributes (order: REQUESTED-TRANSPORT, USERNAME, REALM, NONCE).
	var attrs []byte
	attrs = append(attrs, encodeAttr(attrRequestedTransport, []byte{protoUDP, 0, 0, 0})...)
	attrs = append(attrs, encodeStringAttr(attrUsername, username)...)
	attrs = append(attrs, encodeStringAttr(attrRealm, realm)...)
	attrs = append(attrs, encodeStringAttr(attrNonce, nonce)...)

	return buildAuthenticatedMessage(msgAllocateRequest, txID, attrs, username, realm, password)
}

// buildAuthenticatedMessage builds a STUN message with MESSAGE-INTEGRITY.
// The attrs slice contains pre-encoded attributes (before MI). The header
// length field is adjusted per RFC 5389 Section 15.4 before computing the
// HMAC-SHA1 over the message.
func buildAuthenticatedMessage(msgType uint16, txID [12]byte, attrs []byte, username, realm, password string) []byte {
	// MI attribute = 4-byte header + 20-byte HMAC = 24 bytes.
	const miAttrSize = 24
	msg := make([]byte, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)+miAttrSize))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[stunHeaderSize:], attrs)

	// Compute HMAC-SHA1 over the message (with adjusted length).
	key := longTermKey(username, realm, password)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	integrity := mac.Sum(nil)

	// Append MESSAGE-INTEGRITY attribute.
	msg = append(msg, encodeAttr(attrMessageIntegrity, integrity)...)
	return msg
}

// longTermKey derives the STUN long-term credential key:
//
//	key = MD5(username ":" realm ":" password)
func longTermKey(username, realm, password string) []byte {
	h := md5.New()
	h.Write([]byte(username + ":" + realm + ":" + password))
	return h.Sum(nil)
}

// newTransactionID generates a random 96-bit STUN transaction ID.
func newTransactionID() [12]byte {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("turn: failed to generate transaction ID: " + err.Error())
	}
	return id
}

// =============================================================================
// STUN Message Parsing
// =============================================================================

// parseSTUNMessage parses a STUN message, returning the message type,
// the 12-byte transaction ID, and a map of attribute type -> raw value bytes.
// Per RFC 5389 §7.3.1, only the first occurrence of each attribute is kept.
func parseSTUNMessage(data []byte) (msgType uint16, txID [12]byte, attrs map[uint16][]byte, err error) {
	if len(data) < stunHeaderSize {
		return 0, txID, nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	msgType = binary.BigEndian.Uint16(data[0:2])
	attrLen := int(binary.BigEndian.Uint16(data[2:4]))
	cookie := binary.BigEndian.Uint32(data[4:8])

	if cookie != magicCookie {
		return 0, txID, nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}

	copy(txID[:], data[8:20])

	if stunHeaderSize+attrLen > len(data) {
		return 0, txID, nil, fmt.Errorf("truncated message: need %d bytes, have %d",
			stunHeaderSize+attrLen, len(data))
	}

	attrs = make(map[uint16][]byte)
	offset := stunHeaderSize
	end := stunHeaderSize + attrLen

	for offset+4 <= end {
		aType := binary.BigEndian.Uint16(data[offset : offset+2])
		aLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+aLen > end {
			break
		}

		val := make([]byte, aLen)
		copy(val, data[offset:offset+aLen])

		// RFC 5389 §15: keep only the first occurrence of each attribute.
		if _, exists := attrs[aType]; !exists {
			attrs[aType] = val
		}

		// Advance past value + padding to 4-byte boundary.
		offset += aLen
		if pad := aLen % 4; pad != 0 {
			offset += 4 - pad
		}
	}

	return msgType, txID, attrs, nil
}

// getErrorCode extracts the numeric error code from an ERROR-CODE attribute.
// Returns 0 if the attribute is missing or malformed.
func getErrorCode(attrs map[uint16][]byte) int {
	data, ok := attrs[attrErrorCode]
	if !ok || len(data) < 4 {
		return 0
	}
	class := int(data[2] & 0x07)
	number := int(data[3])
	return class*100 + number
}

// getStringAttr extracts a string attribute value. Returns "" if missing.
func getStringAttr(attrs map[uint16][]byte, attrType uint16) string {
	data, ok := attrs[attrType]
	if !ok {
		return ""
	}
	return string(data)
}

// =============================================================================
// STUN Attribute Encoding
// =============================================================================

// encodeAttr encodes a STUN attribute with TLV format and 4-byte padding.
func encodeAttr(attrType uint16, value []byte) []byte {
	padLen := 0
	if mod := len(value) % 4; mod != 0 {
		padLen = 4 - mod
	}

	buf := make([]byte, 4+len(value)+padLen)
	binary.BigEndian.PutUint16(buf[0:2], attrType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[4:], value)
	return buf
}

// encodeStringAttr encodes a string-valued STUN attribute.
func encodeStringAttr(attrType uint16, value string) []byte {
	return encodeAttr(attrType, []byte(value))
}
