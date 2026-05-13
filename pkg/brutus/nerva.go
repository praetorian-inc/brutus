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

package brutus

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	nervaplugins "github.com/praetorian-inc/nerva/pkg/plugins"
)

// NervaResult represents the JSON output from nerva service discovery.
type NervaResult struct {
	Host      string                 `json:"host,omitempty"`
	IP        string                 `json:"ip"`
	Port      int                    `json:"port"`
	Protocol  string                 `json:"protocol"`
	TLS       bool                   `json:"tls"`
	Transport string                 `json:"transport"`
	Version   string                 `json:"version,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// MapServiceToProtocol maps nerva service names to brutus protocol names.
// Returns an empty string if the service is not supported.
func MapServiceToProtocol(service string) string {
	service = strings.ToLower(service)

	serviceMap := map[string]string{
		"ssh":    "ssh",
		"ftp":    "ftp",
		"telnet": "telnet",
		"vnc":    "vnc",
		"rdp":    "rdp",

		"smb":   "smb",
		"ldap":  "ldap",
		"winrm": "winrm",

		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"postgres":      "postgresql",
		"mssql":         "mssql",
		"mongodb":       "mongodb",
		"redis":         "redis",
		"neo4j":         "neo4j",
		"cassandra":     "cassandra",
		"couchdb":       "couchdb",
		"elasticsearch": "elasticsearch",
		"influxdb":      "influxdb",
		"oracle":        "oracle",

		"smtp": "smtp",
		"imap": "imap",
		"pop3": "pop3",

		"snmp": "snmp",

		"http":  "http",
		"https": "https",

		"browser": "browser",
	}

	if proto, ok := serviceMap[service]; ok {
		return proto
	}

	return ""
}

// ParseNervaTarget converts a "host:port" string into a Nerva plugins.Target.
// If the host is a hostname (not an IP), it performs a context-aware DNS lookup
// to resolve it, allowing cancellation via Ctrl-C / SIGTERM.
func ParseNervaTarget(ctx context.Context, hostPort string) (nervaplugins.Target, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nervaplugins.Target{}, fmt.Errorf("invalid target %q: %w", hostPort, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nervaplugins.Target{}, fmt.Errorf("invalid port in %q: %w", hostPort, err)
	}

	var t nervaplugins.Target

	// Try parsing as IP first; fall back to DNS lookup for hostnames.
	if addr, ok := netip.AddrFromSlice(net.ParseIP(host)); ok {
		t.Address = netip.AddrPortFrom(addr.Unmap(), uint16(port))
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nervaplugins.Target{}, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nervaplugins.Target{}, fmt.Errorf("DNS lookup returned no results for %q", host)
		}
		addr, ok := netip.AddrFromSlice(addrs[0].IP)
		if !ok {
			return nervaplugins.Target{}, fmt.Errorf("invalid IP from DNS for %q", host)
		}
		t.Address = netip.AddrPortFrom(addr.Unmap(), uint16(port))
		t.Host = host
	}

	return t, nil
}

// ServiceToNervaResult converts a Nerva plugins.Service into a NervaResult
// for use with the existing MapServiceToProtocol and brute-force pipeline.
func ServiceToNervaResult(svc *nervaplugins.Service) NervaResult {
	var metadata map[string]interface{}
	if len(svc.Raw) > 0 {
		_ = json.Unmarshal(svc.Raw, &metadata)
	}
	return NervaResult{
		Host:      svc.Host,
		IP:        svc.IP,
		Port:      svc.Port,
		Protocol:  svc.Protocol,
		TLS:       svc.TLS,
		Transport: svc.Transport,
		Version:   svc.Version,
		Metadata:  metadata,
	}
}
