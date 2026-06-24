// Copyright 2026 Praetorian Security, Inc.
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

// pkg/enum/harvest/validate.go
package harvest

import (
	"fmt"
	"regexp"
	"strings"
)

// domainRe is the strict domain-label allowlist (security P0-1). Compiled once.
// Each label is 1-63 chars of [a-z0-9-] not starting/ending with '-'; the TLD is
// 2-63 letters. This rejects anything that is not a plain DNS domain, including
// userinfo authorities, schemes, paths, and control/CRLF bytes.
var domainRe = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// validateDomain normalizes and strictly validates an operator-supplied domain
// before it is ever placed in an outbound URL (security P0-1). It lowercases and
// trims, strips a single leading wildcard ("*." or "%."), and rejects the domain
// unless it matches a strict DNS-label allowlist. Because the domain is the entire
// untrusted input surface for this tool, validation is reject-don't-strip: any
// userinfo hijack (evil.com@internal), scheme, CRLF, control byte, path, or
// traversal segment fails to match the allowlist and is refused.
func validateDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return "", fmt.Errorf("domain is required")
	}

	// Accept a leading wildcard label (crt.sh style) but normalize it away; the
	// host comparison and URL query use the bare domain.
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, "%.")

	if len(d) > 253 {
		return "", fmt.Errorf("domain %q exceeds maximum length", domain)
	}
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain %q: must be a plain DNS domain (no scheme, userinfo, ports, paths, or control characters)", domain)
	}

	return d, nil
}
