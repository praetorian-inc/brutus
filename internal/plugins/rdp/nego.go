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
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// NegoClass is the classification of an RDP negotiation probe.
type NegoClass int

const (
	// NegoScannable means the host accepted standard/SSL negotiation: proceed
	// to the existing WASM session (the probe never skips on this outcome).
	NegoScannable NegoClass = iota
	// NegoNLARequired is a terminal classification: the host requires NLA/CredSSP
	// (HYBRID), so its pre-auth logon screen cannot be reached and the logon
	// backdoor check is not possible. SKIP WASM.
	NegoNLARequired
	// NegoProbeError means the probe could not classify the host (dial/write/read
	// failure, garbage, or malformed framing). Treat as a connect failure and fall
	// through to WASM — a failed probe must NEVER skip detection.
	NegoProbeError
	// NegoUnreachable is a terminal classification: the TCP connection to the
	// host could not be established at all (no SYN-ACK / RST within the connect
	// timeout, or dial error). The host is not scannable, but this is NOT
	// "clean" and NOT "indeterminate": it is a distinct terminal state that is
	// never retried. SKIP WASM. Set ONLY by the nlaProbe dial seam, never by
	// ProbeNLA (which still returns NegoProbeError on its internal errors).
	NegoUnreachable
)

// requestedProtocols / response constants (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1).
const (
	protocolSSL            uint32 = 0x00000001
	protocolHybrid         uint32 = 0x00000002
	protocolHybridEx       uint32 = 0x00000008
	negReqType             byte   = 0x01
	negRspType             byte   = 0x02
	negFailureType         byte   = 0x03
	hybridRequiredByServer uint32 = 0x00000005
	// requestedProtocols offers PROTOCOL_SSL ONLY (0x1), mirroring the real
	// skip_auth scanner which connects without CredSSP. We must NOT offer HYBRID:
	// every modern Windows host supports NLA, so offering it makes the server
	// select HYBRID even when NLA is not required, which would mis-flag scannable
	// hosts as nla_required and skip the backdoor scan (a cardinal-rule violation).
	requestedProtocols uint32 = protocolSSL // = 0x1

	// negResponseMinLen is the smallest TPKT length that can carry an 8-byte
	// negotiation trailer (11 fixed TPKT+X.224 bytes + 8 trailer = 19).
	negResponseMinLen = 19
	// negTPKTVersion is the TPKT version byte (RFC 1006).
	negTPKTVersion = 0x03
	// negResponseMaxLen caps the response we will read to a sane bound.
	negResponseMaxLen = 1024
)

// ProbeNLA performs one round-trip over conn: writes buildNegReq(), reads one
// TPKT-framed response with the given deadline, and classifies it. It NEVER
// acquires a decode slot and does not touch WASM. conn is closed by the caller.
// Any dial/write/read/parse failure maps to NegoProbeError so the caller falls
// through to the full WASM path (the probe must never skip detection on error).
func ProbeNLA(ctx context.Context, conn net.Conn, deadline time.Duration) NegoClass {
	_ = ctx
	if err := conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return NegoProbeError
	}
	if _, err := conn.Write(buildNegReq()); err != nil {
		return NegoProbeError
	}

	frame, err := readRDPFrame(conn)
	if err != nil {
		return NegoProbeError
	}

	class, err := classifyNegResponse(frame)
	if err != nil {
		return NegoProbeError
	}
	return class
}

// buildNegReq returns the 19-byte TPKT+X.224 Connection Request with an embedded
// RDP_NEG_REQ (no cookie). Pure; unit-testable with golden bytes.
func buildNegReq() []byte {
	const total = negResponseMinLen // 19 bytes, no cookie

	req := make([]byte, total)

	// TPKT header (RFC 1006), 4 bytes.
	req[0] = negTPKTVersion
	req[1] = 0x00
	binary.BigEndian.PutUint16(req[2:4], uint16(total))

	// X.224 Connection Request TPDU, 7 bytes.
	req[4] = 0x0E // LI: length of X.224 data after this byte (6 fixed + 8 neg)
	req[5] = 0xE0 // CR + CDT (Connection Request)
	req[6] = 0x00 // DST-REF
	req[7] = 0x00
	req[8] = 0x00 // SRC-REF
	req[9] = 0x00
	req[10] = 0x00 // CLASS / options

	// RDP_NEG_REQ (MS-RDPBCGR 2.2.1.1.1), 8 bytes.
	req[11] = negReqType
	req[12] = 0x00 // flags
	binary.LittleEndian.PutUint16(req[13:15], 0x0008)
	binary.LittleEndian.PutUint32(req[15:19], requestedProtocols)

	return req
}

// classifyNegResponse parses a server negotiation response and returns the class.
// Pure; unit-testable with table-driven byte fixtures. err is non-nil only on
// malformed framing (caller maps to NegoProbeError). Per the cardinal rule, only
// a NEG_FAILURE with code HYBRID_REQUIRED_BY_SERVER yields NegoNLARequired; every
// other well-framed outcome (including any NEG_RSP protocol selection) fails open
// to NegoScannable.
func classifyNegResponse(resp []byte) (NegoClass, error) {
	if len(resp) < 4 {
		return NegoScannable, fmt.Errorf("nego response too short: %d bytes", len(resp))
	}
	if resp[0] != negTPKTVersion {
		return NegoScannable, fmt.Errorf("not a TPKT response: first byte 0x%02x", resp[0])
	}

	length := int(binary.BigEndian.Uint16(resp[2:4]))
	if length < 4 || length > negResponseMaxLen {
		return NegoScannable, fmt.Errorf("invalid TPKT length: %d", length)
	}
	if len(resp) < length {
		return NegoScannable, fmt.Errorf("truncated TPKT: have %d, want %d", len(resp), length)
	}

	// A Connection Confirm without a negotiation block (older/edge servers) has
	// no NEG_RSP trailer: treat as scannable rather than guessing NLA.
	if length < negResponseMinLen {
		return NegoScannable, nil
	}

	// The negotiation structure is the last 8 bytes of the TPKT payload.
	trailer := resp[length-8 : length]
	negType := trailer[0]
	payload := binary.LittleEndian.Uint32(trailer[4:8])

	// MAXIMALLY CONSERVATIVE: the ONLY outcome that yields NegoNLARequired is a
	// NEG_FAILURE whose code is HYBRID_REQUIRED_BY_SERVER. A host that REQUIRES NLA
	// refuses our SSL-only request with exactly that failure code. Selecting a
	// protocol in a NEG_RSP (RDP, SSL, or even an unsolicited HYBRID) never means
	// "NLA required", so every NEG_RSP falls open to NegoScannable. This guarantees
	// the probe can never skip a host the real (skip_auth) scanner could have scanned.
	if negType == negFailureType && payload == hybridRequiredByServer {
		return NegoNLARequired, nil
	}

	// Every other parseable outcome (any NEG_RSP, any other NEG_FAILURE code, or an
	// unknown trailer type) fails open to WASM, which stays authoritative.
	return NegoScannable, nil
}
