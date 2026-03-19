package brutus

import (
	"context"
	"net"
	"time"
)

// DialWithContext dials a network address with a timeout and context support.
// This is a shared helper for plugins that make raw TCP connections (ssh, ftp, pop3, telnet).
func DialWithContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	return dialer.DialContext(ctx, network, address)
}
