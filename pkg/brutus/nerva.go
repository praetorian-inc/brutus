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

import "strings"

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
