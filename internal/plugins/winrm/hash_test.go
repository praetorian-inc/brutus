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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNTHash(t *testing.T) {
	want, err := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	require.NoError(t, err)
	hexHash := hex.EncodeToString(want)

	for _, in := range []string{
		hexHash,
		"NT:" + hexHash,
		"NTLM:" + hexHash,
		"aad3b435b51404eeaad3b435b51404ee:" + hexHash,
	} {
		got, err := ParseNTHash(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
}

func TestParseNTHashRejectsShort(t *testing.T) {
	_, err := ParseNTHash("deadbeef")
	require.Error(t, err)
}

func TestLooksLikeNTHash(t *testing.T) {
	assert.True(t, looksLikeNTHash("0c868a403bfd7a93a3001ef22ef02e3f"))
	assert.True(t, looksLikeNTHash("aad3b435b51404eeaad3b435b51404ee:0c868a403bfd7a93a3001ef22ef02e3f"))
	assert.False(t, looksLikeNTHash("Password123!"))
	assert.False(t, looksLikeNTHash("deadbeef"))
}

func TestNTLMSecretEncodesHash(t *testing.T) {
	h := make([]byte, 16)
	h[0] = 0xaa
	secret := ntlmSecret("", h)
	assert.True(t, len(secret) == len(ntHashPasswordPrefix)+16)
	assert.Equal(t, ntHashPasswordPrefix, secret[:len(ntHashPasswordPrefix)])
}
