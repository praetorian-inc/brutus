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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCredentialsResolve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		creds      AuthCredentials
		wantDomain string
		wantUser   string
	}{
		{"backslash", AuthCredentials{Username: `CORP\admin`}, "CORP", "admin"},
		{"upn", AuthCredentials{Username: "admin@corp.local"}, "corp.local", "admin"},
		{"bare with domain override", AuthCredentials{Username: "admin", Domain: "CORP"}, "CORP", "admin"},
		{"bare no domain", AuthCredentials{Username: "admin"}, "", "admin"},
		{"backslash wins over override", AuthCredentials{Username: `CORP\admin`, Domain: "OTHER"}, "CORP", "admin"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, u := tt.creds.resolve()
			assert.Equal(t, tt.wantDomain, d)
			assert.Equal(t, tt.wantUser, u)
		})
	}
}

func TestAuthCredentialsSecret(t *testing.T) {
	t.Parallel()

	t.Run("password passthrough", func(t *testing.T) {
		t.Parallel()
		c := AuthCredentials{Username: "admin", Password: "Sup3r!"}
		assert.Equal(t, "Sup3r!", c.secret())
	})

	t.Run("hash gets ntlm prefix and lowercased", func(t *testing.T) {
		t.Parallel()
		c := AuthCredentials{Username: "admin", NTHash: "32ED87BDB5FDC5E9CBA88547376818D4"}
		assert.Equal(t, "$NTLM$:32ed87bdb5fdc5e9cba88547376818d4", c.secret())
	})
}

func TestAuthCredentialsValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		creds   AuthCredentials
		wantErr bool
	}{
		{"valid password", AuthCredentials{Username: "admin", Password: "x"}, false},
		{"valid hash", AuthCredentials{Username: "admin", NTHash: "abc"}, false},
		{"no username", AuthCredentials{Password: "x"}, true},
		{"no secret", AuthCredentials{Username: "admin"}, true},
		{"both secrets", AuthCredentials{Username: "admin", Password: "x", NTHash: "y"}, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.creds.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeNTHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare hash", "32ED87BDB5FDC5E9CBA88547376818D4", "32ed87bdb5fdc5e9cba88547376818d4", false},
		{"lm:nt pair", "aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4", "32ed87bdb5fdc5e9cba88547376818d4", false},
		{"whitespace", "  32ed87bdb5fdc5e9cba88547376818d4  ", "32ed87bdb5fdc5e9cba88547376818d4", false},
		{"too short", "abcd", "", true},
		{"non-hex", "zzed87bdb5fdc5e9cba88547376818d4", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeNTHash(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
