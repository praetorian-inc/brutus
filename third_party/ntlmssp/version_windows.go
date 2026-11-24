package ntlmssp

import (
	"syscall"
)

// DefaultVersion returns a pointer to a NTLM Version struct for the OS which
// will be populated on Windows or nil otherwise.
func DefaultVersion() *Version {
	dll := syscall.MustLoadDLL("kernel32.dll")
	p := dll.MustFindProc("GetVersion")
	v, _, _ := p.Call()

	return &Version{
		ProductMajorVersion: uint8(v),
		ProductMinorVersion: uint8(v >> 8),
		ProductBuild:        uint16(v >> 16),
		NTLMRevisionCurrent: NTLMSSPRevisionW2K3,
	}
}
