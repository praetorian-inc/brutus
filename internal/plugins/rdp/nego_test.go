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

// Package rdp — internal test file so we can access unexported buildNegReq,
// classifyNegResponse, and the unexported constants (negRspType, negFailureType,
// hybridRequiredByServer).
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Task 1.1 — golden bytes for buildNegReq
// ---------------------------------------------------------------------------

// TestNegoBuildNegReq verifies that buildNegReq() returns exactly the 19-byte
// TPKT+X.224 Connection Request with embedded RDP_NEG_REQ (no cookie), using
// requestedProtocols = PROTOCOL_SSL = 0x00000001.  Offering HYBRID would cause
// NLA-capable Windows hosts to select HYBRID and be misclassified nla_required,
// skipping the backdoor detection — a cardinal-rule violation.
//
// This test is RED until the developer implements nego.go:buildNegReq().
func TestNegoBuildNegReq(t *testing.T) {
	want := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version=3, reserved=0, length=19 (big-endian)
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI=14, TPDU=0xE0, DST=0, SRC=0, class=0
		0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ: type=0x01, flags=0x00, length=8 (LE)
		0x01, 0x00, 0x00, 0x00, // requestedProtocols = SSL only = 0x1 (little-endian)
	}
	assert.Equal(t, want, buildNegReq())
}

// ---------------------------------------------------------------------------
// Task 1.2 — table-driven test for classifyNegResponse
// ---------------------------------------------------------------------------

// ccWithNeg builds a TPKT+X.224 Connection Confirm (code 0xD0) of total length
// 19 with an 8-byte negotiation trailer so classifyNegResponse has a valid
// framing to parse.  negType is 0x02 (NEG_RSP) or 0x03 (NEG_FAILURE); payload
// is the 4-byte LE value (selectedProtocol or failureCode).
func ccWithNeg(negType byte, payload uint32) []byte {
	buf := make([]byte, 19)
	// TPKT header
	buf[0] = 0x03                            // version
	buf[1] = 0x00                            // reserved
	binary.BigEndian.PutUint16(buf[2:4], 19) // total length = 19
	// X.224 Connection Confirm body
	buf[4] = 0x0E  // LI = 14
	buf[5] = 0xD0  // TPDU code = CC
	buf[6] = 0x00  // DST-REF hi
	buf[7] = 0x00  // DST-REF lo
	buf[8] = 0x00  // SRC-REF hi
	buf[9] = 0x00  // SRC-REF lo
	buf[10] = 0x00 // class/options
	// 8-byte negotiation trailer at bytes 11-18
	buf[11] = negType
	buf[12] = 0x00                               // flags
	binary.LittleEndian.PutUint16(buf[13:15], 8) // length (LE): 8
	binary.LittleEndian.PutUint32(buf[15:19], payload)
	return buf
}

// TestNegoClassify is the 9-case table from plan Task 1.2.
//
// This test is RED until the developer implements nego.go:classifyNegResponse().
func TestNegoClassify(t *testing.T) {
	// A minimal CC without any negotiation trailer (total length = 11).
	ccWithoutNeg := func() []byte {
		buf := make([]byte, 11)
		buf[0] = 0x03
		buf[1] = 0x00
		binary.BigEndian.PutUint16(buf[2:4], 11)
		buf[4] = 0x06 // LI = 6 (standard CC without extensions)
		buf[5] = 0xD0 // TPDU code = CC
		// DST-REF, SRC-REF, class all 0
		return buf
	}

	cases := []struct {
		name    string
		resp    []byte
		want    NegoClass
		wantErr bool
	}{
		{
			name: "rsp_protocol_rdp",
			resp: ccWithNeg(negRspType, 0x0),
			want: NegoScannable,
		},
		{
			name: "rsp_protocol_ssl",
			resp: ccWithNeg(negRspType, 0x1),
			want: NegoScannable,
		},
		{
			// Server selects HYBRID via NEG_RSP: the corrected conservative rule
			// classifies this as NegoScannable.  Only NEG_FAILURE with
			// HYBRID_REQUIRED_BY_SERVER is a definitive "NLA mandatory" signal;
			// a NEG_RSP selecting HYBRID merely means the server preferred it
			// (we requested SSL-only, so a well-behaved server shouldn't reach
			// this branch, but we must not skip detection on ambiguous outcomes).
			name: "rsp_protocol_hybrid",
			resp: ccWithNeg(negRspType, 0x2),
			want: NegoScannable,
		},
		{
			// Same reasoning as rsp_protocol_hybrid.
			name: "rsp_protocol_hybrid_ex",
			resp: ccWithNeg(negRspType, 0x8),
			want: NegoScannable,
		},
		{
			name: "failure_hybrid_required",
			resp: ccWithNeg(negFailureType, hybridRequiredByServer),
			want: NegoNLARequired,
		},
		{
			name: "failure_ssl_not_allowed",
			resp: ccWithNeg(negFailureType, 0x2),
			want: NegoScannable,
		},
		{
			name: "cc_without_neg_block",
			resp: ccWithoutNeg(),
			want: NegoScannable,
		},
		{
			name:    "garbage_non_tpkt",
			resp:    []byte{0xFF, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "short_read",
			resp:    []byte{0x03, 0x00, 0x00}, // only 3 bytes — no full TPKT header
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyNegResponse(tc.resp)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, tc.name)
		})
	}
}

// ---------------------------------------------------------------------------
// Task 1.3 — fakeConn + ProbeNLA round-trip tests
// ---------------------------------------------------------------------------

// fakeConn implements net.Conn backed by a bytes.Buffer for reads and records
// all bytes written so tests can assert the exact wire request sent.
// SetDeadline/SetReadDeadline/SetWriteDeadline are no-ops (return nil).
// Close is a no-op (returns nil).
type fakeConn struct {
	readBuf bytes.Buffer
	written bytes.Buffer
}

func newFakeConn(response []byte) *fakeConn {
	fc := &fakeConn{}
	fc.readBuf.Write(response)
	return fc
}

func (fc *fakeConn) Read(b []byte) (int, error)  { return fc.readBuf.Read(b) }
func (fc *fakeConn) Write(b []byte) (int, error) { return fc.written.Write(b) }
func (fc *fakeConn) Close() error                { return nil }

func (fc *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (fc *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (fc *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (fc *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (fc *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// TestProbeNLA_ScannableSSL verifies that a NEG_RSP selecting PROTOCOL_SSL
// returns NegoScannable, and that the exact wire bytes written to the connection
// equal buildNegReq() — i.e., requestedProtocols = 0x01 (SSL only, not
// SSL|HYBRID).  The SSL-only probe is required so that NLA-capable Windows hosts
// select SSL (or reject with NEG_FAILURE) rather than always selecting HYBRID.
//
// This test is RED until the developer implements nego.go:ProbeNLA().
func TestProbeNLA_ScannableSSL(t *testing.T) {
	fc := newFakeConn(ccWithNeg(negRspType, protocolSSL))
	got := ProbeNLA(context.Background(), fc, 2*time.Second)
	assert.Equal(t, NegoScannable, got)
	assert.Equal(t, buildNegReq(), fc.written.Bytes(),
		"written request must be byte-equal to buildNegReq() (requestedProtocols=0x01, SSL only)")
}

// TestProbeNLA_HybridRequired verifies that a NEG_FAILURE with
// HYBRID_REQUIRED_BY_SERVER returns NegoNLARequired — this is the ONLY outcome
// that correctly signals the host mandates NLA.  The wire bytes written must
// equal buildNegReq() (requestedProtocols = 0x01, SSL only).
func TestProbeNLA_HybridRequired(t *testing.T) {
	fc := newFakeConn(ccWithNeg(negFailureType, hybridRequiredByServer))
	got := ProbeNLA(context.Background(), fc, 2*time.Second)
	assert.Equal(t, NegoNLARequired, got)
	assert.Equal(t, buildNegReq(), fc.written.Bytes(),
		"written request must be byte-equal to buildNegReq() (requestedProtocols=0x01, SSL only)")
}

// TestProbeNLA_Garbage verifies that a non-TPKT (first byte != 0x03) response
// returns NegoProbeError.
func TestProbeNLA_Garbage(t *testing.T) {
	fc := newFakeConn([]byte{0xFF})
	got := ProbeNLA(context.Background(), fc, 2*time.Second)
	assert.Equal(t, NegoProbeError, got)
}

// TestProbeNLA_EmptyEOF verifies that an empty read buffer (immediate EOF)
// returns NegoProbeError.
func TestProbeNLA_EmptyEOF(t *testing.T) {
	fc := newFakeConn([]byte{}) // nothing to read → EOF on first Read
	got := ProbeNLA(context.Background(), fc, 2*time.Second)
	assert.Equal(t, NegoProbeError, got)
}

// ---------------------------------------------------------------------------
// Task 1 — NegoUnreachable distinct class test
// ---------------------------------------------------------------------------

// TestNegoUnreachable_IsDistinctClass verifies that NegoUnreachable is a 4th,
// distinct NegoClass value. All four values must be distinct — if any two share
// the same iota, the map length will be less than 4 and the require.Len will
// fail. This test is RED until the developer adds NegoUnreachable to nego.go.
func TestNegoUnreachable_IsDistinctClass(t *testing.T) {
	classes := map[NegoClass]string{
		NegoScannable:   "scannable",
		NegoNLARequired: "nla_required",
		NegoProbeError:  "probe_error",
		NegoUnreachable: "unreachable",
	}
	require.Len(t, classes, 4, "all four NegoClass values must be distinct")
}
