package ntlmssp

import (
	"syscall"
	"unsafe"
)

// DefaultDomain returns the Windows domain that the host is joined to. This
// will never be successful on non-Windows as there's no standard API.
func DefaultDomain() (string, error) {
	var domain *uint16
	var status uint32
	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return "", err
	}
	defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	// Not joined to a domain
	if status != syscall.NetSetupDomainName {
		return "", nil
	}

	return syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(domain))[:]), nil
}
