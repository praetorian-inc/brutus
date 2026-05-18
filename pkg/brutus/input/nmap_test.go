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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempFile creates a temporary file with the given content and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestLoadNmapFile_BasicParse(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host starttime="1" endtime="2">
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="host.example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" tunnel="ssl" product="nginx"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 3) // SSH, HTTP, HTTPS (closed port excluded)

	// SSH
	assert.Equal(t, "192.168.1.1", results[0].IP)
	assert.Equal(t, "host.example.com", results[0].Host)
	assert.Equal(t, 22, results[0].Port)
	assert.Equal(t, "ssh", results[0].Protocol)
	assert.False(t, results[0].TLS)
	assert.Equal(t, "OpenSSH 8.9p1", results[0].Version)
	assert.Equal(t, "tcp", results[0].Transport)

	// HTTP (port 80)
	assert.Equal(t, 80, results[1].Port)
	assert.Equal(t, "http", results[1].Protocol)
	assert.False(t, results[1].TLS)

	// HTTPS (port 443 with tunnel="ssl") — upgraded from http to https
	assert.Equal(t, 443, results[2].Port)
	assert.Equal(t, "https", results[2].Protocol)
	assert.True(t, results[2].TLS)
}

func TestLoadNmapFile_SkipsDownHosts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh"/></port></ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-down.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestLoadNmapFile_MultipleHosts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
  <host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
    </ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-multi.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "10.0.0.1", results[0].IP)
	assert.Equal(t, "ssh", results[0].Protocol)
	assert.Equal(t, "10.0.0.2", results[1].IP)
	assert.Equal(t, "rdp", results[1].Protocol) // ms-wbt-server normalized
}

func TestLoadNmapFile_NmapServiceNormalization(t *testing.T) {
	tests := []struct {
		nmapName string
		expected string
	}{
		{"ms-sql-s", "mssql"},
		{"ms-sql", "mssql"},
		{"microsoft-ds", "smb"},
		{"netbios-ssn", "smb"},
		{"ms-wbt-server", "rdp"},
		{"http-proxy", "http"},
		{"http-alt", "http"},
		{"ssl/http", "https"},
		{"https-alt", "https"},
		{"ssh", "ssh"},
		{"mysql", "mysql"},
		{"postgresql", "postgresql"},
	}
	for _, tt := range tests {
		t.Run(tt.nmapName, func(t *testing.T) {
			result := normalizeNmapService(tt.nmapName)
			mapped := MapServiceToProtocol(result)
			assert.Equal(t, tt.expected, mapped)
		})
	}
}

func TestLoadNmapFile_FileNotFound(t *testing.T) {
	_, err := LoadNmapFile("/nonexistent/nmap.xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening nmap file")
}

func TestLoadNmapFile_InvalidXML(t *testing.T) {
	file := writeTempFile(t, "bad.xml", "not xml at all <><>")
	_, err := LoadNmapFile(file)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing nmap XML")
}

func TestLoadNmapFile_EmptyFile(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun></nmaprun>`
	file := writeTempFile(t, "empty.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestLoadNmapFile_TargetAddr(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-addr.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "10.0.0.5:22", results[0].TargetAddr())
}

func TestLoadNmapFile_UDPPorts(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161"><state state="open"/><service name="snmp"/></port>
    </ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-udp.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "snmp", results[0].Protocol)
	assert.Equal(t, "udp", results[0].Transport)
}

func TestLoadNmapFile_UnknownServiceEmpty(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306"><state state="open"/><service name="tcpwrapped"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-unknown.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 2)
	// tcpwrapped is unknown — Protocol should be empty
	assert.Equal(t, "", results[0].Protocol)
	assert.Equal(t, 3306, results[0].Port)
	// ssh is known
	assert.Equal(t, "ssh", results[1].Protocol)
}

func TestLoadNmapFile_HostnamePreferred(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="db.internal" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql"/></port></ports>
  </host>
</nmaprun>`

	file := writeTempFile(t, "nmap-hostname.xml", xml)
	results, err := LoadNmapFile(file)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "db.internal", results[0].Host)
	assert.Equal(t, "10.0.0.1", results[0].IP)
	// TargetAddr prefers hostname
	assert.Equal(t, "db.internal:5432", results[0].TargetAddr())
}
