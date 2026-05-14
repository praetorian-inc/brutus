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
	"net/netip"
	"testing"

	nervaplugins "github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapServiceToProtocol_WinRM(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		expected string
	}{
		{name: "lowercase winrm", service: "winrm", expected: "winrm"},
		{name: "uppercase WINRM", service: "WINRM", expected: "winrm"},
		{name: "mixed case WinRM", service: "WinRM", expected: "winrm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapServiceToProtocol(tt.service)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapServiceToProtocol_ExistingMappings(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		{"ssh", "ssh"},
		{"ftp", "ftp"},
		{"smb", "smb"},
		{"ldap", "ldap"},
		{"http", "http"},
		{"https", "https"},
		{"mysql", "mysql"},
		{"postgresql", "postgresql"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			result := MapServiceToProtocol(tt.service)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapServiceToProtocol_Oracle(t *testing.T) {
	assert.Equal(t, "oracle", MapServiceToProtocol("oracle"))
	assert.Equal(t, "oracle", MapServiceToProtocol("Oracle"))
}

func TestParseNervaTarget_IP(t *testing.T) {
	target, err := ParseNervaTarget(context.Background(), "192.168.1.1:22")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("192.168.1.1:22"), target.Address)
	assert.Empty(t, target.Host)
}

func TestParseNervaTarget_IPv6(t *testing.T) {
	target, err := ParseNervaTarget(context.Background(), "[::1]:8080")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("[::1]:8080"), target.Address)
	assert.Empty(t, target.Host)
}

func TestParseNervaTarget_Hostname(t *testing.T) {
	target, err := ParseNervaTarget(context.Background(), "localhost:443")
	require.NoError(t, err)
	assert.NotZero(t, target.Address.Port())
	assert.Equal(t, uint16(443), target.Address.Port())
	assert.Equal(t, "localhost", target.Host)
}

func TestParseNervaTarget_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no port", "192.168.1.1"},
		{"empty", ""},
		{"bad port", "192.168.1.1:abc"},
		{"port out of range", "192.168.1.1:99999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseNervaTarget(context.Background(), tt.input)
			assert.Error(t, err)
		})
	}
}

func TestServiceToNervaResult(t *testing.T) {
	raw, _ := json.Marshal(map[string]interface{}{
		"banner": "OpenSSH_8.9",
	})

	svc := nervaplugins.Service{
		Host:      "example.com",
		IP:        "93.184.216.34",
		Port:      22,
		Protocol:  "ssh",
		TLS:       false,
		Transport: "tcp",
		Version:   "OpenSSH_8.9",
		Raw:       raw,
	}

	nrv := ServiceToNervaResult(&svc)

	assert.Equal(t, "example.com", nrv.Host)
	assert.Equal(t, "93.184.216.34", nrv.IP)
	assert.Equal(t, 22, nrv.Port)
	assert.Equal(t, "ssh", nrv.Protocol)
	assert.False(t, nrv.TLS)
	assert.Equal(t, "tcp", nrv.Transport)
	assert.Equal(t, "OpenSSH_8.9", nrv.Version)
	assert.Equal(t, "OpenSSH_8.9", nrv.Metadata["banner"])
}

func TestServiceToNervaResult_NilRaw(t *testing.T) {
	svc := nervaplugins.Service{
		IP:       "10.0.0.1",
		Port:     3306,
		Protocol: "mysql",
	}

	nrv := ServiceToNervaResult(&svc)
	assert.Nil(t, nrv.Metadata)
	assert.Equal(t, "mysql", nrv.Protocol)
}

func TestServiceToNervaResult_TLS(t *testing.T) {
	svc := nervaplugins.Service{
		IP:       "10.0.0.1",
		Port:     443,
		Protocol: "https",
		TLS:      true,
	}

	nrv := ServiceToNervaResult(&svc)
	assert.True(t, nrv.TLS)
}

func TestClassifyStdinLine_JSON(t *testing.T) {
	line := `{"ip":"10.0.0.1","port":22,"protocol":"ssh"}`
	parsed, err := ClassifyStdinLine(line)
	require.NoError(t, err)
	assert.Equal(t, StdinLineJSON, parsed.Type)
	assert.Equal(t, "10.0.0.1", parsed.NervaResult.IP)
	assert.Equal(t, 22, parsed.NervaResult.Port)
	assert.Equal(t, "ssh", parsed.NervaResult.Protocol)
}

func TestClassifyStdinLine_JSONInvalid(t *testing.T) {
	_, err := ClassifyStdinLine(`{not valid json}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestClassifyStdinLine_URI(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		protocol  string
		transport string
		host      string
		port      string
		hostPort  string
		tls       bool
	}{
		{
			name:      "ssh",
			line:      "ssh://192.168.1.1:22",
			protocol:  "ssh",
			transport: "tcp",
			host:      "192.168.1.1",
			port:      "22",
			hostPort:  "192.168.1.1:22",
		},
		{
			name:      "rdp",
			line:      "rdp://10.0.0.50:3389",
			protocol:  "rdp",
			transport: "tcp",
			host:      "10.0.0.50",
			port:      "3389",
			hostPort:  "10.0.0.50:3389",
		},
		{
			name:      "https with TLS",
			line:      "https://myhost.local:443",
			protocol:  "https",
			transport: "tcp",
			host:      "myhost.local",
			port:      "443",
			hostPort:  "myhost.local:443",
			tls:       true,
		},
		{
			name:      "snmp+udp",
			line:      "snmp+udp://10.0.0.1:161",
			protocol:  "snmp",
			transport: "udp",
			host:      "10.0.0.1",
			port:      "161",
			hostPort:  "10.0.0.1:161",
		},
		{
			name:      "postgres alias",
			line:      "postgres://10.0.0.1:5432",
			protocol:  "postgresql",
			transport: "tcp",
			host:      "10.0.0.1",
			port:      "5432",
			hostPort:  "10.0.0.1:5432",
		},
		{
			name:      "http no TLS",
			line:      "http://192.168.1.1:8080",
			protocol:  "http",
			transport: "tcp",
			host:      "192.168.1.1",
			port:      "8080",
			hostPort:  "192.168.1.1:8080",
		},
		{
			name:      "IPv6 URI",
			line:      "ssh://[::1]:22",
			protocol:  "ssh",
			transport: "tcp",
			host:      "::1",
			port:      "22",
			hostPort:  "[::1]:22",
		},
		{
			name:      "ldaps TLS",
			line:      "ldaps://10.0.0.1:636",
			protocol:  "ldap",
			transport: "tcp",
			host:      "10.0.0.1",
			port:      "636",
			hostPort:  "10.0.0.1:636",
			tls:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ClassifyStdinLine(tt.line)
			require.NoError(t, err)
			assert.Equal(t, StdinLineURI, parsed.Type)
			assert.Equal(t, tt.protocol, parsed.Protocol)
			assert.Equal(t, tt.transport, parsed.Transport)
			assert.Equal(t, tt.host, parsed.Host)
			assert.Equal(t, tt.port, parsed.Port)
			assert.Equal(t, tt.hostPort, parsed.HostPort)
			assert.Equal(t, tt.tls, parsed.TLS)
		})
	}
}

func TestClassifyStdinLine_HostPort(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"IPv4", "192.168.1.1:22"},
		{"IPv4 high port", "10.0.0.1:8080"},
		{"IPv6", "[::1]:8080"},
		{"hostname", "myhost.local:3306"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ClassifyStdinLine(tt.line)
			require.NoError(t, err)
			assert.Equal(t, StdinLineHostPort, parsed.Type)
			assert.Equal(t, tt.line, parsed.Raw)
		})
	}
}

func TestClassifyStdinLine_Invalid(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"empty", ""},
		{"no port", "192.168.1.1"},
		{"bad port", "192.168.1.1:abc"},
		{"port out of range", "192.168.1.1:99999"},
		{"uri no port", "ssh://192.168.1.1"},
		{"uri no host", "ssh://:22"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ClassifyStdinLine(tt.line)
			assert.Error(t, err)
		})
	}
}
