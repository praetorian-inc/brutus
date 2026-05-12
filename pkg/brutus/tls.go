package brutus

import "crypto/tls"

// BuildTLSConfig returns a *tls.Config based on the TLS mode string.
//
// Modes:
//   - "verify": full certificate verification (InsecureSkipVerify=false)
//   - "skip-verify": allow self-signed certs (InsecureSkipVerify=true)
//   - "disable" (default): returns nil (no TLS)
func BuildTLSConfig(tlsMode string) *tls.Config {
	switch tlsMode {
	case "verify":
		return &tls.Config{
			InsecureSkipVerify: false,
		}
	case "skip-verify":
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User explicitly chose skip-verify
		}
	default:
		return nil
	}
}
