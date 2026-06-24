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
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNegotiationRequest(t *testing.T) {
	t.Parallel()

	req := buildNegotiationRequest(true, protocolHybrid|protocolSSL)

	// TPKT header.
	require.Len(t, req, 19, "cookie-less negotiation request is exactly 19 bytes")
	assert.Equal(t, byte(0x03), req[0], "TPKT version")
	assert.Equal(t, uint16(19), binary.BigEndian.Uint16(req[2:4]), "TPKT length")

	// X.224 Connection Request.
	assert.Equal(t, byte(14), req[4], "X.224 LI")
	assert.Equal(t, byte(0xE0), req[5], "X.224 CR CDT")

	// RDP_NEG_REQ.
	assert.Equal(t, negTypeRequest, req[11], "neg type = request")
	assert.Equal(t, negReqRestrictedAdminRequired, req[12], "restricted-admin flag set")
	assert.Equal(t, uint16(8), binary.LittleEndian.Uint16(req[13:15]), "neg length")
	assert.Equal(t, protocolHybrid|protocolSSL, binary.LittleEndian.Uint32(req[15:19]), "requested protocols")
}

func TestBuildNegotiationRequest_NoRestrictedAdmin(t *testing.T) {
	t.Parallel()

	req := buildNegotiationRequest(false, protocolHybrid)
	assert.Equal(t, byte(0), req[12], "no flags when restricted admin not requested")
}

// craftNegResponse builds a TPKT-framed X.224 Connection Confirm carrying an
// 8-byte RDP negotiation structure of the given type.
func craftNegResponse(negType, flags byte, payload uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = negType
	neg[1] = flags
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], payload)

	x224 := []byte{
		0xD0,       // CC CDT (Connection Confirm)
		0x00, 0x00, // DST-REF
		0x12, 0x34, // SRC-REF
		0x00, // CLASS OPTION
	}
	x224 = append(x224, neg...)
	pdu := append([]byte{byte(len(x224))}, x224...)
	total := 4 + len(pdu)
	out := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
	return append(out, pdu...)
}

func TestParseNegotiationResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         []byte
		wantType     byte
		wantFlags    byte
		wantSelProto uint32
		wantFailCode uint32
		wantErr      bool
	}{
		{
			name:         "restricted admin supported",
			data:         craftNegResponse(negTypeResponse, respFlagRestrictedAdminSupported|respFlagExtendedClientData, protocolHybrid),
			wantType:     negTypeResponse,
			wantFlags:    respFlagRestrictedAdminSupported | respFlagExtendedClientData,
			wantSelProto: protocolHybrid,
		},
		{
			name:      "response without restricted admin",
			data:      craftNegResponse(negTypeResponse, respFlagExtendedClientData, protocolHybrid),
			wantType:  negTypeResponse,
			wantFlags: respFlagExtendedClientData,

			wantSelProto: protocolHybrid,
		},
		{
			name:         "negotiation failure",
			data:         craftNegResponse(negTypeFailure, 0, 0x05),
			wantType:     negTypeFailure,
			wantFailCode: 0x05,
		},
		{
			name:     "no negotiation structure",
			data:     []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00},
			wantType: 0,
		},
		{
			name:    "short response",
			data:    []byte{0x03, 0x00},
			wantErr: true,
		},
		{
			name:    "not a connection confirm",
			data:    []byte{0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			negType, flags, selProto, failCode, err := parseNegotiationResponse(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantType, negType)
			assert.Equal(t, tt.wantFlags, flags)
			assert.Equal(t, tt.wantSelProto, selProto)
			assert.Equal(t, tt.wantFailCode, failCode)
		})
	}
}

// stubServer accepts one connection, reads the negotiation request, and replies
// with the supplied response bytes.
func stubServer(t *testing.T, response []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain the client's negotiation request (TPKT-framed).
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		total := int(binary.BigEndian.Uint16(header[2:4]))
		if total > 4 {
			_, _ = io.ReadFull(conn, make([]byte, total-4))
		}
		_, _ = conn.Write(response)
	}()

	return ln.Addr().String()
}

func TestProbeRestrictedAdmin_Supported(t *testing.T) {
	t.Parallel()
	addr := stubServer(t, craftNegResponse(negTypeResponse, respFlagRestrictedAdminSupported, protocolHybrid))

	res, err := ProbeRestrictedAdmin(context.Background(), addr, 2*time.Second, "")
	require.NoError(t, err)
	assert.True(t, res.Reachable)
	assert.True(t, res.NegotiationReceived)
	assert.True(t, res.RestrictedAdminSupported)
	assert.True(t, res.NLARequired)
	assert.Equal(t, VerdictSupported, res.Verdict)
}

func TestProbeRestrictedAdmin_NotSupported(t *testing.T) {
	t.Parallel()
	addr := stubServer(t, craftNegResponse(negTypeResponse, respFlagExtendedClientData, protocolHybrid))

	res, err := ProbeRestrictedAdmin(context.Background(), addr, 2*time.Second, "")
	require.NoError(t, err)
	assert.False(t, res.RestrictedAdminSupported)
	assert.Equal(t, VerdictNotSupported, res.Verdict)
}

func TestProbeRestrictedAdmin_Failure(t *testing.T) {
	t.Parallel()
	addr := stubServer(t, craftNegResponse(negTypeFailure, 0, 0x05))

	res, err := ProbeRestrictedAdmin(context.Background(), addr, 2*time.Second, "")
	require.NoError(t, err)
	assert.True(t, res.NegotiationReceived)
	assert.Equal(t, VerdictUnknown, res.Verdict)
	assert.Equal(t, uint32(0x05), res.FailureCode)
}

func TestProbeRestrictedAdmin_Unreachable(t *testing.T) {
	t.Parallel()
	// Reserved TEST-NET-1 address, should not connect within the timeout.
	res, err := ProbeRestrictedAdmin(context.Background(), "192.0.2.1:3389", 500*time.Millisecond, "")
	require.Error(t, err)
	assert.False(t, res.Reachable)
}
