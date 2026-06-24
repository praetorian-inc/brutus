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
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// RDP security protocols (MS-RDPBCGR 2.2.1.1.1, requestedProtocols).
const (
	protocolRDP      uint32 = 0x00000000
	protocolSSL      uint32 = 0x00000001
	protocolHybrid   uint32 = 0x00000002 // CredSSP / NLA
	protocolHybridEx uint32 = 0x00000008
)

// RDP_NEG_REQ request flags (MS-RDPBCGR 2.2.1.1.1).
const (
	negReqRestrictedAdminRequired byte = 0x01
)

// RDP negotiation structure type codes (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1 / 2.2.1.2.2).
const (
	negTypeRequest  byte = 0x01 // TYPE_RDP_NEG_REQ
	negTypeResponse byte = 0x02 // TYPE_RDP_NEG_RSP
	negTypeFailure  byte = 0x03 // TYPE_RDP_NEG_FAILURE
)

// RDP_NEG_RSP response flags (MS-RDPBCGR 2.2.1.2.1).
const (
	respFlagExtendedClientData       uint8 = 0x01
	respFlagRestrictedAdminSupported uint8 = 0x08 // credential-less logon over CredSSP
	respFlagRedirectedAuthSupported  uint8 = 0x10 // Remote Credential Guard
)

// Verdict strings for a restricted-admin probe.
const (
	VerdictSupported    = "supported"
	VerdictNotSupported = "not-supported"
	VerdictUnknown      = "unknown"
)

// maxTPKTLen bounds the negotiation response we are willing to read. A negotiation
// confirm is tiny (19 bytes); anything large indicates a non-RDP or hostile peer.
const maxTPKTLen = 4096

// RestrictedAdminResult is the outcome of a single host's Restricted Admin Mode probe.
type RestrictedAdminResult struct {
	Target string `json:"target"`
	// Reachable indicates the TCP connection succeeded.
	Reachable bool `json:"reachable"`
	// NegotiationReceived indicates the server returned a parseable RDP negotiation
	// response or failure (i.e. it speaks RDP negotiation / supports TLS or NLA).
	NegotiationReceived bool `json:"negotiation_received"`
	// SelectedProtocol is the server-selected security protocol (from RDP_NEG_RSP).
	SelectedProtocol uint32 `json:"selected_protocol"`
	// ResponseFlags is the raw RDP_NEG_RSP flags byte.
	ResponseFlags uint8 `json:"response_flags"`
	// RestrictedAdminSupported is true when the server advertised
	// RESTRICTED_ADMIN_MODE_SUPPORTED (0x08).
	RestrictedAdminSupported bool `json:"restricted_admin_supported"`
	// RedirectedAuthSupported is true when the server advertised
	// REDIRECTED_AUTHENTICATION_MODE_SUPPORTED (0x10, Remote Credential Guard).
	RedirectedAuthSupported bool `json:"redirected_auth_supported"`
	// NLARequired is true when the selected protocol is CredSSP/NLA (HYBRID).
	NLARequired bool `json:"nla_required"`
	// FailureCode is the RDP_NEG_FAILURE code, when the server rejected negotiation.
	FailureCode uint32 `json:"failure_code,omitempty"`
	// Verdict is one of VerdictSupported / VerdictNotSupported / VerdictUnknown.
	Verdict string `json:"verdict"`
	// Detail is a human-readable explanation of the verdict.
	Detail string `json:"detail"`
}

// buildNegotiationRequest builds an X.224 Connection Request (TPKT-framed) carrying an
// RDP_NEG_REQ. When requestRestrictedAdmin is set, the RESTRICTED_ADMIN_MODE_REQUIRED
// flag is included so the server advertises restricted-admin support in its response.
func buildNegotiationRequest(requestRestrictedAdmin bool, protocols uint32) []byte {
	var flags byte
	if requestRestrictedAdmin {
		flags |= negReqRestrictedAdminRequired
	}

	// RDP_NEG_REQ (8 bytes): type, flags, length(LE u16)=8, requestedProtocols(LE u32).
	negReq := make([]byte, 8)
	negReq[0] = negTypeRequest
	negReq[1] = flags
	binary.LittleEndian.PutUint16(negReq[2:4], 8)
	binary.LittleEndian.PutUint32(negReq[4:8], protocols)

	// X.224 Connection Request fixed header (6 bytes) + RDP_NEG_REQ.
	x224 := []byte{
		0xE0,       // CR CDT (Connection Request)
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00, // CLASS OPTION
	}
	x224 = append(x224, negReq...)

	// LI = length of the X.224 data following the LI octet itself.
	pdu := append([]byte{byte(len(x224))}, x224...)

	// TPKT header (version 3, reserved 0, total length BE u16).
	total := 4 + len(pdu)
	out := make([]byte, 0, total)
	out = append(out, 0x03, 0x00, byte(total>>8), byte(total))
	out = append(out, pdu...)
	return out
}

// parseNegotiationResponse parses a TPKT-framed X.224 Connection Confirm and extracts
// the embedded RDP negotiation structure, if any.
//
// Returns negType=0 (with nil error) when the confirm carries no negotiation structure,
// which indicates the server fell back to standard RDP security.
func parseNegotiationResponse(data []byte) (negType, flags byte, selectedProto, failureCode uint32, err error) {
	if len(data) < 11 {
		return 0, 0, 0, 0, fmt.Errorf("short response (%d bytes)", len(data))
	}
	if data[0] != 0x03 {
		return 0, 0, 0, 0, fmt.Errorf("not a TPKT response (0x%02x)", data[0])
	}
	// X.224 Connection Confirm code is the high nibble of the byte at offset 5 (0xD0).
	if data[5]&0xF0 != 0xD0 {
		return 0, 0, 0, 0, fmt.Errorf("not an X.224 connection confirm (0x%02x)", data[5])
	}
	// Negotiation structure (8 bytes) begins after the 6-byte fixed X.224 CC header.
	if len(data) < 19 {
		return 0, 0, 0, 0, nil // no negotiation structure present
	}

	negType = data[11]
	flags = data[12]
	payload := binary.LittleEndian.Uint32(data[15:19])
	switch negType {
	case negTypeResponse:
		selectedProto = payload
	case negTypeFailure:
		failureCode = payload
	}
	return negType, flags, selectedProto, failureCode, nil
}

// readTPKT reads a single TPKT-framed PDU from conn and returns the full bytes
// (header included).
func readTPKT(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x03 {
		return nil, fmt.Errorf("invalid TPKT version 0x%02x", header[0])
	}
	total := int(binary.BigEndian.Uint16(header[2:4]))
	if total < 4 || total > maxTPKTLen {
		return nil, fmt.Errorf("invalid TPKT length %d", total)
	}
	body := make([]byte, total-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// ProbeRestrictedAdmin performs an unauthenticated RDP negotiation against target and
// reports whether the server advertises Restricted Admin Mode support. It never sends
// credentials and touches no WASM — a fast, safe probe suitable for mass scanning.
//
// The returned result is always non-nil; err is set for connection/protocol errors
// (the result still carries partial state, e.g. Reachable).
func ProbeRestrictedAdmin(ctx context.Context, target string, timeout time.Duration, proxyURL string) (*RestrictedAdminResult, error) {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)
	res := &RestrictedAdminResult{Target: target, Verdict: VerdictUnknown}

	conn, err := brutus.DialWithProxy(ctx, "tcp", addr, timeout, proxyURL)
	if err != nil {
		res.Detail = "connection failed"
		return res, brutus.WrapConnError(err)
	}
	defer func() { _ = conn.Close() }()
	res.Reachable = true

	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := buildNegotiationRequest(true, protocolHybrid|protocolSSL)
	if _, err := conn.Write(req); err != nil {
		res.Detail = "write failed"
		return res, fmt.Errorf("connection error: write negotiation: %w", err)
	}

	resp, err := readTPKT(conn)
	if err != nil {
		res.Detail = "no negotiation response"
		return res, fmt.Errorf("connection error: read negotiation: %w", err)
	}

	negType, flags, selProto, failCode, err := parseNegotiationResponse(resp)
	if err != nil {
		res.Detail = "unparseable negotiation response"
		return res, fmt.Errorf("parse negotiation: %w", err)
	}

	switch negType {
	case negTypeResponse:
		res.NegotiationReceived = true
		res.SelectedProtocol = selProto
		res.ResponseFlags = flags
		res.RestrictedAdminSupported = flags&respFlagRestrictedAdminSupported != 0
		res.RedirectedAuthSupported = flags&respFlagRedirectedAuthSupported != 0
		res.NLARequired = selProto&(protocolHybrid|protocolHybridEx) != 0
		if res.RestrictedAdminSupported {
			res.Verdict = VerdictSupported
			res.Detail = "server advertised RESTRICTED_ADMIN_MODE_SUPPORTED"
		} else {
			res.Verdict = VerdictNotSupported
			res.Detail = "server did not advertise restricted admin support"
		}
	case negTypeFailure:
		res.NegotiationReceived = true
		res.FailureCode = failCode
		res.Verdict = VerdictUnknown
		res.Detail = "negotiation failure: " + negFailureString(failCode)
	default:
		res.Verdict = VerdictUnknown
		res.Detail = "no RDP negotiation structure (standard RDP security or NLA disabled)"
	}

	return res, nil
}

// negFailureString maps an RDP_NEG_FAILURE code to its MS-RDPBCGR name.
func negFailureString(code uint32) string {
	switch code {
	case 0x01:
		return "SSL_REQUIRED_BY_SERVER"
	case 0x02:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 0x03:
		return "SSL_CERT_NOT_ON_SERVER"
	case 0x04:
		return "INCONSISTENT_FLAGS"
	case 0x05:
		return "HYBRID_REQUIRED_BY_SERVER"
	case 0x06:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	default:
		return fmt.Sprintf("unknown(0x%02x)", code)
	}
}

// ProtocolName renders a selected security protocol bitmask for display.
func ProtocolName(proto uint32) string {
	return protocolString(proto)
}

// protocolString renders a selected security protocol bitmask for display.
func protocolString(proto uint32) string {
	switch {
	case proto&protocolHybridEx != 0:
		return "HYBRID_EX (NLA/CredSSP)"
	case proto&protocolHybrid != 0:
		return "HYBRID (NLA/CredSSP)"
	case proto&protocolSSL != 0:
		return "SSL/TLS"
	case proto == protocolRDP:
		return "standard RDP security"
	default:
		return fmt.Sprintf("0x%08x", proto)
	}
}
