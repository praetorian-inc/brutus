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

package input

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	nervaplugins "github.com/praetorian-inc/nerva/pkg/plugins"
)

// NervaResult represents the JSON output from nerva service discovery.
type NervaResult struct {
	Host            string                 `json:"host,omitempty"`
	IP              string                 `json:"ip"`
	Port            int                    `json:"port"`
	Protocol        string                 `json:"protocol"`
	TLS             bool                   `json:"tls"`
	Transport       string                 `json:"transport"`
	Version         string                 `json:"version,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
	AnonymousAccess bool                   `json:"anonymous_access,omitempty"`
}

// TargetAddr returns "host:port" for this result, preferring the hostname
// over the IP address when available.
func (nrv *NervaResult) TargetAddr() string {
	host := nrv.IP
	if nrv.Host != "" {
		host = nrv.Host
	}
	return fmt.Sprintf("%s:%d", host, nrv.Port)
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
		"turn": "turn",

		"docker":     "docker",
		"kubernetes": "kubernetes",
		"k8s":        "kubernetes",
		"kubelet":    "kubernetes",

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

	// Determine anonymous access: use the canonical top-level field first,
	// then fall back to per-service metadata (auth_required: false).
	anonAccess := svc.AnonymousAccess
	if !anonAccess && metadata != nil {
		if authReq, ok := metadata["auth_required"]; ok {
			if b, ok := authReq.(bool); ok && !b {
				anonAccess = true
			}
		}
	}

	return NervaResult{
		Host:            svc.Host,
		IP:              svc.IP,
		Port:            svc.Port,
		Protocol:        svc.Protocol,
		TLS:             svc.TLS,
		Transport:       svc.Transport,
		Version:         svc.Version,
		Metadata:        metadata,
		AnonymousAccess: anonAccess,
	}
}

// HasNoAuth returns true if Nerva detected that the service does not require
// authentication. Checks both the top-level AnonymousAccess field and the
// per-service auth_required metadata (used by PostgreSQL, Redis plugins).
// This works regardless of whether the NervaResult was created from
// ServiceToNervaResult (library path) or JSON unmarshal (stdin path).
func (nrv *NervaResult) HasNoAuth() bool {
	if nrv.AnonymousAccess {
		return true
	}
	if nrv.Metadata != nil {
		if authReq, ok := nrv.Metadata["auth_required"]; ok {
			if b, ok := authReq.(bool); ok && !b {
				return true
			}
		}
	}
	return false
}

// StdinLineType classifies a line read from stdin.
type StdinLineType int

const (
	// StdinLineJSON indicates a Nerva JSON object (starts with '{').
	StdinLineJSON StdinLineType = iota
	// StdinLineURI indicates a URI-scheme line like ssh://host:port.
	StdinLineURI
	// StdinLineHostPort indicates a bare host:port that needs fingerprinting.
	StdinLineHostPort
)

// ParsedStdinLine holds the result of classifying and parsing one stdin line.
type ParsedStdinLine struct {
	Type StdinLineType
	Raw  string // original trimmed line

	// Set for StdinLineJSON.
	NervaResult NervaResult

	// Set for StdinLineURI.
	Protocol  string // normalized protocol (e.g. "ssh", "postgresql")
	Transport string // "tcp" (default) or "udp"
	Host      string // hostname or IP (without brackets for IPv6)
	Port      string // port number as string
	HostPort  string // "host:port" suitable for passing to runSingleTarget
	TLS       bool   // true for https, ldaps, imaps, pop3s, smtps
}

// tlsProtocols lists protocols that imply TLS when used as a URI scheme.
var tlsProtocols = map[string]bool{
	"https": true,
	"ldaps": true,
	"imaps": true,
	"pop3s": true,
	"smtps": true,
}

// ClassifyStdinLine determines the format of a single stdin line and parses it.
// It returns a ParsedStdinLine with the Type field set to indicate whether the
// line is Nerva JSON, a URI-scheme target, or a bare host:port.
func ClassifyStdinLine(line string) (ParsedStdinLine, error) {
	if line == "" {
		return ParsedStdinLine{}, fmt.Errorf("empty line")
	}

	// JSON: starts with '{'
	if line[0] == '{' {
		var nrv NervaResult
		if err := json.Unmarshal([]byte(line), &nrv); err != nil {
			return ParsedStdinLine{}, fmt.Errorf("invalid JSON: %w", err)
		}
		return ParsedStdinLine{
			Type:        StdinLineJSON,
			Raw:         line,
			NervaResult: nrv,
		}, nil
	}

	// URI: contains "://"
	if strings.Contains(line, "://") {
		return parseURILine(line)
	}

	// Bare host:port: validate with net.SplitHostPort
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		return ParsedStdinLine{}, fmt.Errorf("invalid target %q: %w", line, err)
	}
	if host == "" || port == "" {
		return ParsedStdinLine{}, fmt.Errorf("invalid target %q: missing host or port", line)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return ParsedStdinLine{}, fmt.Errorf("invalid port in %q: %w", line, err)
	}

	return ParsedStdinLine{
		Type: StdinLineHostPort,
		Raw:  line,
	}, nil
}

// parseURILine parses a URI-scheme line like "ssh://192.168.1.1:22" or
// "snmp+udp://10.0.0.1:161".
//
// Nerva's default (non-JSON) output appends a resolved IP in parentheses,
// e.g. "ssh://github.com:22 (20.205.243.166)". Since valid URIs never
// contain unencoded spaces, we strip everything after the first space.
func parseURILine(line string) (ParsedStdinLine, error) {
	if idx := strings.IndexByte(line, ' '); idx >= 0 {
		line = line[:idx]
	}

	u, err := url.Parse(line)
	if err != nil {
		return ParsedStdinLine{}, fmt.Errorf("invalid URI %q: %w", line, err)
	}

	// Parse scheme: "proto" or "proto+transport"
	scheme := strings.ToLower(u.Scheme)
	proto := scheme
	transport := "tcp"
	if idx := strings.IndexByte(scheme, '+'); idx >= 0 {
		proto = scheme[:idx]
		transport = scheme[idx+1:]
	}

	// Check TLS before normalizing (ldaps, imaps, etc. are in tlsProtocols).
	tls := tlsProtocols[proto]

	// Normalize protocol via MapServiceToProtocol (handles aliases like postgres -> postgresql).
	// For TLS variants not in the service map (ldaps, imaps, pop3s, smtps), strip trailing 's'
	// to get the base protocol name.
	if mapped := MapServiceToProtocol(proto); mapped != "" {
		proto = mapped
	} else if tls && len(proto) > 1 && proto[len(proto)-1] == 's' {
		if base := MapServiceToProtocol(proto[:len(proto)-1]); base != "" {
			proto = base
		}
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return ParsedStdinLine{}, fmt.Errorf("invalid URI %q: missing host", line)
	}
	if port == "" {
		return ParsedStdinLine{}, fmt.Errorf("invalid URI %q: missing port", line)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return ParsedStdinLine{}, fmt.Errorf("invalid port in URI %q: %w", line, err)
	}

	// Build host:port string (re-bracket IPv6 for net compatibility)
	hostPort := net.JoinHostPort(host, port)

	return ParsedStdinLine{
		Type:      StdinLineURI,
		Raw:       line,
		Protocol:  proto,
		Transport: transport,
		Host:      host,
		Port:      port,
		HostPort:  hostPort,
		TLS:       tls,
	}, nil
}
