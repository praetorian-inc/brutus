// +build !windows

package ntlmssp

// DefaultDomain returns the Windows domain that the host is joined to. This
// will never be successful on non-Windows as there's no standard API.
func DefaultDomain() (string, error) {
	return "", nil
}
