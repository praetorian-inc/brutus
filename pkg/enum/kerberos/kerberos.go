// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kerberos

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Result represents the result of a Kerberos user enumeration attempt.
type Result struct {
	Username  string
	Realm     string
	Exists    bool
	NoPreAuth bool
	Error     error
	Duration  time.Duration
}

// EnumUser attempts to enumerate whether a username exists in the Kerberos realm
// by sending an AS-REQ without pre-authentication data and interpreting the response.
//
// Returns:
// - KDC_ERR_C_PRINCIPAL_UNKNOWN (6) → user does not exist
// - KDC_ERR_PREAUTH_REQUIRED (25) → user exists
// - AS-REP success → user exists AND has "Do not require Kerberos preauthentication" set
func EnumUser(ctx context.Context, kdcAddr, realm, username string, timeout time.Duration) *Result {
	start := time.Now()
	result := &Result{
		Username: username,
		Realm:    realm,
	}

	// Build AS-REQ
	asReqBytes, err := buildASReq(username, realm)
	if err != nil {
		result.Error = fmt.Errorf("building AS-REQ: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Send to KDC
	response, err := sendKerberosTCP(ctx, kdcAddr, asReqBytes, timeout)
	if err != nil {
		result.Error = fmt.Errorf("sending AS-REQ: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Parse response
	// Try AS-REP first (success - user exists with no preauth)
	var asRep messages.ASRep
	err = asRep.Unmarshal(response)
	if err == nil {
		// AS-REP received - user exists AND has no preauth required
		result.Exists = true
		result.NoPreAuth = true
		result.Duration = time.Since(start)
		return result
	}

	// Not AS-REP, try KRB-ERROR
	var krbErr messages.KRBError
	err = krbErr.Unmarshal(response)
	if err != nil {
		result.Error = fmt.Errorf("parsing response: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Interpret error code
	switch krbErr.ErrorCode {
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		// User does not exist
		result.Exists = false
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		// User exists (preauth required)
		result.Exists = true
		result.NoPreAuth = false
	default:
		// Other error
		result.Error = fmt.Errorf("KDC error: %s", errorcode.Lookup(krbErr.ErrorCode))
	}

	result.Duration = time.Since(start)
	return result
}

// buildASReq constructs a Kerberos AS-REQ message without pre-authentication data.
func buildASReq(username, realm string) ([]byte, error) {
	// Uppercase realm per Kerberos convention
	realm = strings.ToUpper(realm)

	// Generate random nonce
	nonceInt, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	nonce := int(nonceInt.Int64())

	// Client principal name
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}

	// Service principal name (krbtgt/REALM)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	// Till time: 24 hours from now
	till := time.Now().UTC().Add(24 * time.Hour)

	// Encryption types: AES256, AES128, RC4-HMAC (most common)
	etypes := []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.RC4_HMAC,
	}

	// Construct AS-REQ with empty PAData (no pre-authentication)
	asReq := messages.ASReq{
		KDCReqFields: messages.KDCReqFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_AS_REQ,
			PAData:  types.PADataSequence{}, // Empty - no preauth
			ReqBody: messages.KDCReqBody{
				KDCOptions: types.NewKrbFlags(),
				CName:      cname,
				Realm:      realm,
				SName:      sname,
				Till:       till,
				Nonce:      nonce,
				EType:      etypes,
			},
		},
	}

	// Marshal to bytes
	return asReq.Marshal()
}

// sendKerberosTCP sends a Kerberos message over TCP and reads the response.
// Kerberos TCP protocol uses 4-byte big-endian length prefix.
func sendKerberosTCP(ctx context.Context, addr string, data []byte, timeout time.Duration) ([]byte, error) {
	// Add :88 if no port specified.
	// net.SplitHostPort fails when there is no port, so use that to detect bare addresses.
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		addr = net.JoinHostPort(addr, "88")
	}

	// Dial with context
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing KDC: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Set deadline — use the earlier of timeout or context deadline.
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("setting deadline: %w", err)
	}

	// Write 4-byte length prefix + data
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))

	if _, err := conn.Write(length); err != nil {
		return nil, fmt.Errorf("writing length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("writing data: %w", err)
	}

	// Read 4-byte response length
	respLength := make([]byte, 4)
	if _, err := io.ReadFull(conn, respLength); err != nil {
		return nil, fmt.Errorf("reading response length: %w", err)
	}

	respSize := binary.BigEndian.Uint32(respLength)
	if respSize > 1024*1024 { // 1MB sanity check
		return nil, fmt.Errorf("response too large: %d bytes", respSize)
	}

	// Read response body
	response := make([]byte, respSize)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return response, nil
}
