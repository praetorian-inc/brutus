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

package winrm

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

const ntHashLen = 16

// ntHashPasswordPrefix is understood by the vendored ntlmssp ntowfV1 as "this
// string is already the 16-byte NT hash".
const ntHashPasswordPrefix = "\x00NTLMHASH\x00"

// ParseNTHash accepts 32 hex digits, optional NT:/NTLM: prefix, or LM:NT
// (LM half ignored).
func ParseNTHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	upper := strings.ToUpper(s)
	switch {
	case strings.HasPrefix(upper, "NTLM:"):
		s = s[5:]
	case strings.HasPrefix(upper, "NT:"):
		s = s[3:]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == '-' || r == ':' {
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	if len(s) != ntHashLen*2 {
		return nil, fmt.Errorf("NT hash must be %d hex digits, got %d", ntHashLen*2, len(s))
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("NT hash: %w", err)
	}
	return out, nil
}

// looksLikeNTHash is true for 32 hex digits or LM:NT. Used so brutus creds can
// pass a hash in -p without a separate flag.
func looksLikeNTHash(s string) bool {
	_, err := ParseNTHash(s)
	if err != nil {
		return false
	}
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, ":") {
		return true
	}
	hexOnly := true
	for _, r := range trimmed {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			hexOnly = false
			break
		}
	}
	return hexOnly && len(trimmed) == 32
}

func ntlmSecret(password string, hash []byte) string {
	if len(hash) == ntHashLen {
		return ntHashPasswordPrefix + string(hash)
	}
	if looksLikeNTHash(password) {
		h, err := ParseNTHash(password)
		if err == nil {
			return ntHashPasswordPrefix + string(h)
		}
	}
	return password
}
