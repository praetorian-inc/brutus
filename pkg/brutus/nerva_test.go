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
