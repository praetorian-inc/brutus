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
	"encoding/hex"
	"fmt"
	"strings"
)

// ntlmHashPrefix is the marker sspi-rs uses to recognize a password value that is
// actually an NT hash (hex) rather than a plaintext password. The NTLMv2
// computation then derives the response from the hash directly (pass-the-hash).
// Must match sspi's crate::ntlm::hash::NTLM_HASH_PREFIX.
const ntlmHashPrefix = "$NTLM$:"

// AuthCredentials holds the credentials for an authenticated RDP session. Exactly
// one of Password or NTHash must be set.
type AuthCredentials struct {
	// Username may be "DOMAIN\\user", "user@domain", or a bare "user".
	Username string
	// Domain optionally overrides the domain when Username is a bare name.
	Domain string
	// Password is a plaintext password (mutually exclusive with NTHash).
	Password string
	// NTHash is a 32-char hex NT hash for pass-the-hash (mutually exclusive with Password).
	NTHash string
}

// resolve splits the username into (domain, user), honoring an explicit Domain
// override and the "DOMAIN\\user" / "user@domain" conventions.
func (c AuthCredentials) resolve() (domain, user string) {
	if d, u := parseDomainUsername(c.Username); d != "" {
		return d, u
	}
	if at := strings.LastIndex(c.Username, "@"); at >= 0 {
		return c.Username[at+1:], c.Username[:at]
	}
	return c.Domain, c.Username
}

// secret returns the value to pass as the connector password. For pass-the-hash
// the NT hash is encoded with the sspi NTLM hash prefix; otherwise the plaintext
// password is used as-is.
func (c AuthCredentials) secret() string {
	if c.NTHash != "" {
		return ntlmHashPrefix + strings.ToLower(c.NTHash)
	}
	return c.Password
}

// Validate checks that the credentials are well-formed and usable.
func (c AuthCredentials) Validate() error {
	if strings.TrimSpace(c.Username) == "" {
		return fmt.Errorf("username is required")
	}
	if c.Password == "" && c.NTHash == "" {
		return fmt.Errorf("a password or NT hash is required")
	}
	if c.Password != "" && c.NTHash != "" {
		return fmt.Errorf("password and NT hash are mutually exclusive")
	}
	return nil
}

// NormalizeNTHash validates and normalizes an NT hash for pass-the-hash. It accepts
// either a bare 32-char hex NT hash or an Impacket-style "LMHASH:NTHASH" pair (the
// NT half is used). The returned hash is lowercase hex.
func NormalizeNTHash(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", fmt.Errorf("empty NT hash")
	}
	// Accept LM:NT (take the NT half).
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[i+1:]
	}
	h = strings.ToLower(h)
	if len(h) != 32 {
		return "", fmt.Errorf("NT hash must be 32 hex characters (got %d)", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("NT hash must be hexadecimal: %w", err)
	}
	return h, nil
}
