// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package snmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	// DefaultPort is the standard SNMP port.
	DefaultPort = 161

	// SysDescrOID is the OID for system description (banner).
	SysDescrOID = "1.3.6.1.2.1.1.1.0"
)

func init() {
	brutus.Register("snmp", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements SNMP community string authentication.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "snmp"
}

// Test attempts SNMP community string authentication.
//
// For SNMP, the "password" parameter is the community string to test.
// The "username" parameter is ignored (SNMP v1/v2c uses community strings only).
//
// Returns Result with:
// - Success=true, Error=nil: Valid community string (received response)
// - Success=false, Error=nil: Invalid community string (no response/timeout)
// - Success=false, Error!=nil: Connection/network error (unreachable, etc.)
//
// Note: SNMP uses UDP, so timeout = invalid community string is expected behavior.
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration, pluginCfg brutus.PluginConfig) *brutus.Result {
	start := time.Now()

	result := brutus.NewResult("snmp", target, username, password)
	defer func() { result.Duration = time.Since(start) }()

	// Parse target into host and port
	host, port, err := parseTarget(target)
	if err != nil {
		result.Error = fmt.Errorf("connection error: invalid target: %w", err)
		return result
	}

	// Create SNMP client
	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: password, // Community string is the "password"
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0, // No retries - we want to detect failure quickly
		Context:   ctx,
	}

	// Connect (establishes UDP socket)
	if connectErr := snmp.Connect(); connectErr != nil {
		result.Error = brutus.WrapConnError(connectErr)
		return result
	}
	defer func() { _ = snmp.Conn.Close() }()

	// Try to get sysDescr - this validates the community string
	oids := []string{SysDescrOID}
	response, err := snmp.Get(oids)

	if err != nil {
		// Check if context was canceled
		if ctx.Err() != nil {
			result.Error = brutus.WrapConnError(ctx.Err())
			return result
		}

		// Timeout or no response = invalid community string for UDP
		// This is NOT a connection error - it's authentication failure
		result.Error = nil
		return result
	}

	// Check SNMP protocol error
	if response.Error != gosnmp.NoError {
		// SNMP error response - might indicate invalid community
		// or OID not supported. Treat as auth failure.
		result.Error = nil
		return result
	}

	// Success! Extract banner from sysDescr
	result.Success = true
	if len(response.Variables) > 0 {
		switch v := response.Variables[0].Value.(type) {
		case []byte:
			result.Banner = string(v)
		case string:
			result.Banner = v
		}
	}

	return result
}

// parseTarget splits target into host and port.
// Supports formats: "host", "host:port", "[ipv6]:port"
func parseTarget(target string) (host string, port int, err error) {
	// Check for IPv6 with port
	if strings.HasPrefix(target, "[") {
		// IPv6 format: [::1]:161
		var portStr string
		host, portStr, err = net.SplitHostPort(target)
		if err != nil {
			// IPv6 without port: [::1]
			return strings.Trim(target, "[]"), DefaultPort, nil
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %s", portStr)
		}
		return host, port, nil
	}

	// Check for port separator
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %s", parts[1])
		}
		return parts[0], port, nil
	}

	// No port specified, use default
	return target, DefaultPort, nil
}
