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
	"testing"

	"github.com/stretchr/testify/assert"
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
