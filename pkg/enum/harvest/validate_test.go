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

package harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateDomain covers the mandatory security test (P0-1): strict allowlist
// rejects every dangerous input shape and accepts only valid DNS domains.
func TestValidateDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantOut string // non-empty => expect success with this normalized value
		wantErr bool
	}{
		// --- ACCEPT ---
		{
			name:    "simple domain",
			input:   "acme.com",
			wantOut: "acme.com",
		},
		{
			name:    "multi-label domain",
			input:   "mail.acme.co.uk",
			wantOut: "mail.acme.co.uk",
		},
		{
			name:    "normalizes uppercase",
			input:   "ACME.COM",
			wantOut: "acme.com",
		},
		{
			name:    "trims leading/trailing whitespace",
			input:   "  acme.com  ",
			wantOut: "acme.com",
		},
		{
			name:    "strips leading wildcard *.",
			input:   "*.acme.com",
			wantOut: "acme.com",
		},
		{
			name:    "strips leading wildcard %.",
			input:   "%.acme.com",
			wantOut: "acme.com",
		},

		// --- REJECT ---
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "userinfo hijack evil.com@internal",
			input:   "evil.com@internal",
			wantErr: true,
		},
		{
			name:    "userinfo hijack with port",
			input:   "evil.com@internal:8080",
			wantErr: true,
		},
		{
			name:    "CRLF injection percent-encoded",
			input:   "a.com%0d%0a",
			wantErr: true,
		},
		{
			// Control bytes are rejected BEFORE TrimSpace (reject-don't-strip contract).
			// Trailing CR+LF must be refused outright, not silently consumed.
			name:    "trailing CRLF rejected",
			input:   "a.com\r\n",
			wantErr: true,
		},
		{
			// Embedded CR (0x0D) — header injection vector.
			name:    "embedded CR rejected",
			input:   "a.com\rinternal",
			wantErr: true,
		},
		{
			// Embedded LF (0x0A) — header injection vector.
			name:    "embedded LF rejected",
			input:   "a.com\nb.com",
			wantErr: true,
		},
		{
			// CRLF in the middle of the domain (header injection risk) is rejected.
			name:    "mid-domain CRLF raw bytes",
			input:   "a.com\r\nX-Injected: evil",
			wantErr: true,
		},
		{
			// NUL byte (0x00) must be refused.
			name:    "control byte NUL rejected",
			input:   "a.com\x00",
			wantErr: true,
		},
		{
			// Horizontal tab (0x09) is a control byte — must be refused.
			name:    "control byte tab rejected",
			input:   "a.com\t",
			wantErr: true,
		},
		{
			name:    "leading scheme http://",
			input:   "http://a.com",
			wantErr: true,
		},
		{
			name:    "leading scheme https://",
			input:   "https://a.com",
			wantErr: true,
		},
		{
			name:    "path traversal component",
			input:   "a.com/../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "domain with port",
			input:   "a.com:443",
			wantErr: true,
		},
		{
			name:    "bare label without TLD",
			input:   "localhost",
			wantErr: true,
		},
		{
			name:    "IP address v4",
			input:   "192.168.1.1",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := validateDomain(tc.input)
			if tc.wantErr {
				require.Error(t, err, "expected an error for input %q", tc.input)
			} else {
				require.NoError(t, err, "unexpected error for input %q", tc.input)
				assert.Equal(t, tc.wantOut, out)
			}
		})
	}
}
