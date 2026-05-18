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

// Package creds provides protocol filtering for the "brutus creds" subcommand.
package creds

// httpProtocols lists protocols handled by the "web" subcommand (not "creds").
// Keep in sync with the identical map in pkg/brutus/web/web.go.
var httpProtocols = map[string]bool{
	"http":    true,
	"https":   true,
	"browser": true,
}

// IsCredsProtocol returns true for non-HTTP, non-SNMP protocols handled by the
// "creds" subcommand. SNMP has its own dedicated subcommand ("brutus snmp").
func IsCredsProtocol(protocol string) bool {
	return !httpProtocols[protocol] && protocol != "snmp"
}
