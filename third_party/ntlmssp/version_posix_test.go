package ntlmssp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultVersion(t *testing.T) {
	assert.Equal(t, (*Version)(nil), DefaultVersion())
}
