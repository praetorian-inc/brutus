package brutus

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"
)

// ReadLine reads a newline-terminated line from a bufio.Reader and trims whitespace.
// This is a shared helper for text-protocol plugins (FTP, POP3).
func ReadLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// DialWithContext dials a network address with a timeout and context support.
// This is a shared helper for plugins that make raw TCP connections (ssh, ftp, pop3, telnet).
func DialWithContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	return dialer.DialContext(ctx, network, address)
}
