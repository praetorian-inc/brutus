package ntlmssp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlagsToString(t *testing.T) {
	tables := []struct {
		got  uint32
		want string
	}{
		{
			0xe202b232,
			"NTLM_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_TARGET_TYPE_SERVER | NTLMSSP_NEGOTIATE_VERSION | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56",
		},
	}

	for _, table := range tables {
		want := flagsToString(table.got)
		assert.Equal(t, table.want, want)
	}
}
