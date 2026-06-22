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

package main

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestIsAllowedVerificationURL
// ---------------------------------------------------------------------------

func TestIsAllowedVerificationURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		allowed bool
	}{
		// --- ALLOWED cases ---
		{
			name:    "microsoft.com subdomain with path",
			raw:     "https://login.microsoft.com/device",
			allowed: true,
		},
		{
			name:    "microsoft.com base host with path",
			raw:     "https://microsoft.com/devicelogin",
			allowed: true,
		},
		{
			name:    "microsoftonline.com subdomain oauth path",
			raw:     "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
			allowed: true,
		},
		{
			name:    "microsoftonline.com base host exact",
			raw:     "https://login.microsoftonline.com",
			allowed: true,
		},
		{
			name:    "case-insensitive host matching",
			raw:     "https://MICROSOFT.COM/x",
			allowed: true,
		},

		// --- REJECTED cases ---
		{
			name:    "http scheme rejected",
			raw:     "http://login.microsoft.com/device",
			allowed: false,
		},
		{
			name:    "wrong host entirely",
			raw:     "https://evil.com/device",
			allowed: false,
		},
		{
			name:    "suffix match without dot must be rejected (notmicrosoft.com)",
			raw:     "https://notmicrosoft.com",
			allowed: false,
		},
		{
			name:    "security-critical: lookalike host microsoft.com.evil.com must be rejected",
			raw:     "https://microsoft.com.evil.com/x",
			allowed: false,
		},
		{
			name:    "ftp scheme rejected",
			raw:     "ftp://login.microsoft.com",
			allowed: false,
		},
		{
			name:    "empty string rejected",
			raw:     "",
			allowed: false,
		},
		{
			name:    "unparseable URL rejected",
			raw:     "://bad",
			allowed: false,
		},
		{
			name:    "malformed percent-encoding rejected",
			raw:     "%zz",
			allowed: false,
		},
		{
			name:    "empty host rejected",
			raw:     "https:///device",
			allowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedVerificationURL(tc.raw)
			assert.Equal(t, tc.allowed, got,
				"isAllowedVerificationURL(%q) = %v, want %v", tc.raw, got, tc.allowed)
		})
	}
}

// ---------------------------------------------------------------------------
// TestBrowserCommand
// ---------------------------------------------------------------------------

func TestBrowserCommand(t *testing.T) {
	const url = "https://login.microsoft.com/device"

	tests := []struct {
		name      string
		goos      string
		wantName  string
		wantArgs  []string
		wantError bool
	}{
		{
			name:      "darwin opens with open",
			goos:      "darwin",
			wantName:  "open",
			wantArgs:  []string{url},
			wantError: false,
		},
		{
			name:      "windows opens with rundll32",
			goos:      "windows",
			wantName:  "rundll32",
			wantArgs:  []string{"url.dll,FileProtocolHandler", url},
			wantError: false,
		},
		{
			name:      "linux opens with xdg-open",
			goos:      "linux",
			wantName:  "xdg-open",
			wantArgs:  []string{url},
			wantError: false,
		},
		{
			name:      "freebsd opens with xdg-open",
			goos:      "freebsd",
			wantName:  "xdg-open",
			wantArgs:  []string{url},
			wantError: false,
		},
		{
			name:      "openbsd opens with xdg-open",
			goos:      "openbsd",
			wantName:  "xdg-open",
			wantArgs:  []string{url},
			wantError: false,
		},
		{
			name:      "netbsd opens with xdg-open",
			goos:      "netbsd",
			wantName:  "xdg-open",
			wantArgs:  []string{url},
			wantError: false,
		},
		{
			name:      "unsupported GOOS returns error",
			goos:      "plan9",
			wantName:  "",
			wantArgs:  nil,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, args, err := browserCommand(tc.goos, url)

			if tc.wantError {
				require.Error(t, err, "expected error for GOOS %q", tc.goos)
				assert.Empty(t, name, "expected empty name on error for GOOS %q", tc.goos)
				return
			}

			require.NoError(t, err, "unexpected error for GOOS %q", tc.goos)
			assert.Equal(t, tc.wantName, name, "executable name for GOOS %q", tc.goos)
			assert.True(t, reflect.DeepEqual(tc.wantArgs, args),
				"args for GOOS %q: got %v, want %v", tc.goos, args, tc.wantArgs)
		})
	}
}
