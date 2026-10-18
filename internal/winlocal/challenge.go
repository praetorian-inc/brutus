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

package winlocal

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	ntlmSignature = "NTLMSSP\x00"
	ntlmChallenge = 2
	ntlmAuth      = 3

	avEOL          = 0
	avComputerName = 1
)

// ComputerName returns the NetBIOS computer name from an NTLM challenge.
//
// msg may be a raw Type 2 message or a buffer that contains one (SPNEGO,
// CredSSP). The name comes from MsvAvNbComputerName, not TargetName. On a
// domain member TargetName is the AD domain; using it is a domain login.
func ComputerName(msg []byte) (string, bool) {
	msg, ok := ntlmMessage(msg, ntlmChallenge)
	if !ok || len(msg) < 48 {
		return "", false
	}
	infoLen := binary.LittleEndian.Uint16(msg[40:42])
	infoOff := binary.LittleEndian.Uint32(msg[44:48])
	if infoLen == 0 || int(infoOff) < 0 || int(infoOff)+int(infoLen) > len(msg) {
		return "", false
	}
	return avString(msg[infoOff:infoOff+uint32(infoLen)], avComputerName)
}

// AuthenticateDomain returns the domain field of an NTLM Type 3 message.
// Used to prove what was sent on the wire.
func AuthenticateDomain(msg []byte) (string, bool) {
	msg, ok := ntlmMessage(msg, ntlmAuth)
	if !ok || len(msg) < 36 {
		return "", false
	}
	n := binary.LittleEndian.Uint16(msg[28:30])
	off := binary.LittleEndian.Uint32(msg[32:36])
	if n == 0 || int(off) < 0 || int(off)+int(n) > len(msg) {
		return "", n == 0
	}
	return decodeUTF16LE(msg[off : off+uint32(n)]), true
}

func ntlmMessage(buf []byte, typ uint32) ([]byte, bool) {
	sig := []byte(ntlmSignature)
	for i := 0; i+len(sig)+4 <= len(buf); i++ {
		if string(buf[i:i+len(sig)]) != ntlmSignature {
			continue
		}
		msg := buf[i:]
		if binary.LittleEndian.Uint32(msg[8:12]) == typ {
			return msg, true
		}
	}
	return nil, false
}

func avString(info []byte, want uint16) (string, bool) {
	for len(info) >= 4 {
		id := binary.LittleEndian.Uint16(info[0:2])
		n := binary.LittleEndian.Uint16(info[2:4])
		info = info[4:]
		if int(n) > len(info) {
			return "", false
		}
		val := info[:n]
		info = info[n:]
		if id == avEOL {
			break
		}
		if id == want {
			s := decodeUTF16LE(val)
			if s == "" {
				return "", false
			}
			return s, true
		}
	}
	return "", false
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// ChallengeMessage builds an NTLM Type 2 message. targetName is the challenge
// TargetName (the AD domain on a member). computer is MsvAvNbComputerName and
// may be empty. Flags include REQUEST_TARGET and TARGET_INFO.
func ChallengeMessage(targetName, computer string) []byte {
	target := utf16LE(targetName)
	var info []byte
	if computer != "" {
		info = append(info, avPair(avComputerName, utf16LE(computer))...)
	}
	if targetName != "" {
		info = append(info, avPair(2, utf16LE(targetName))...)
	}
	info = append(info, 0, 0, 0, 0)

	const header = 48
	msg := make([]byte, header+len(target)+len(info))
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmChallenge)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(msg[16:20], header)
	// UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED | TARGET_INFO | 128 | KEY_EXCH | 56
	binary.LittleEndian.PutUint32(msg[20:24], 0x00000001|0x00000004|0x00000200|0x00008000|0x00080000|0x00800000|0x20000000|0x40000000|0x80000000)
	infoOff := header + len(target)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(infoOff))
	copy(msg[header:], target)
	copy(msg[infoOff:], info)
	return msg
}

func avPair(id uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.LittleEndian.PutUint16(b[0:2], id)
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

// NegotiateMessage is an NTLM Type 1 message that asks for target info.
// The flags match what go-smb2 sends, so a Windows server returns
// MsvAvNbComputerName in the challenge.
func NegotiateMessage() []byte {
	msg := make([]byte, 40)
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], 0x00000001|0x00000004|0x00000010|0x00000200|0x00008000|0x00080000|0x00800000|0x02000000|0x20000000|0x40000000|0x80000000)
	msg[32] = 0x0a
	msg[39] = 0x0f
	return msg
}
