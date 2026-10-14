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
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in     string
		user   string
		domain string
		local  bool
	}{
		{in: "Administrator", user: "Administrator", local: true},
		{in: `.\Administrator`, user: "Administrator", local: true},
		{in: `\Administrator`, user: "Administrator", local: true},
		{in: `CORP\Administrator`, user: "Administrator", domain: "CORP", local: false},
		{in: `CORP\SUB\Administrator`, user: `SUB\Administrator`, domain: "CORP", local: false},
		{in: "admin@corp.local", user: "admin", domain: "corp.local", local: false},
		{in: `CORP\admin@corp.local`, user: "admin@corp.local", domain: "CORP", local: false},
		{in: "", user: "", local: true},
	}
	for _, tc := range tests {
		got := Parse(tc.in)
		if got.User != tc.user || got.Domain != tc.domain || got.Local != tc.local {
			t.Errorf("Parse(%q) = %+v, want user=%q domain=%q local=%v", tc.in, got, tc.user, tc.domain, tc.local)
		}
	}
}

func TestComputerNameIgnoresTargetName(t *testing.T) {
	msg := challenge("CORP", "SERVER01")
	name, ok := ComputerName(msg)
	if !ok || name != "SERVER01" {
		t.Fatalf("ComputerName() = %q, %v; want SERVER01", name, ok)
	}
	// TargetName is the domain. It must not be returned as the computer.
	if name == "CORP" {
		t.Fatal("computer name fell back to TargetName")
	}
}

func TestComputerNameMissing(t *testing.T) {
	if _, ok := ComputerName(challenge("CORP", "")); ok {
		t.Fatal("challenge without MsvAvNbComputerName must not yield a name")
	}
	if _, ok := ComputerName([]byte("not ntlm")); ok {
		t.Fatal("non-NTLM buffer must not yield a name")
	}
}

func TestAuthenticateDomain(t *testing.T) {
	msg := authenticate("SERVER01", "Administrator")
	domain, ok := AuthenticateDomain(msg)
	if !ok || domain != "SERVER01" {
		t.Fatalf("AuthenticateDomain() = %q, %v", domain, ok)
	}
}

func challenge(targetName, computer string) []byte {
	target := utf16LE(targetName)
	var info []byte
	if computer != "" {
		info = append(info, av(avComputerName, utf16LE(computer))...)
	}
	if targetName != "" {
		info = append(info, av(2, utf16LE(targetName))...)
	}
	info = append(info, 0, 0, 0, 0)

	const header = 48
	msg := make([]byte, header+len(target)+len(info))
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmChallenge)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(msg[16:20], header)
	// UNICODE | REQUEST_TARGET | NTLM | TARGET_INFO
	binary.LittleEndian.PutUint32(msg[20:24], 0x00000001|0x00000004|0x00000200|0x00800000)
	infoOff := header + len(target)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(infoOff))
	copy(msg[header:], target)
	copy(msg[infoOff:], info)
	return msg
}

func authenticate(domain, user string) []byte {
	d := utf16LE(domain)
	u := utf16LE(user)
	const header = 88
	msg := make([]byte, header+len(d)+len(u))
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:12], ntlmAuth)
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(d)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(d)))
	binary.LittleEndian.PutUint32(msg[32:36], header)
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(u)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(u)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(header+len(d)))
	copy(msg[header:], d)
	copy(msg[header+len(d):], u)
	return msg
}

func av(id uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.LittleEndian.PutUint16(b[0:2], id)
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}
