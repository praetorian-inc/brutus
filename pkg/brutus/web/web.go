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

// Package web provides HTTP/web-panel domain logic for the "brutus web"
// subcommand: protocol filtering, HTTP auth routing, and browser/AI credential
// research.
package web

// httpProtocols lists protocols handled by the "web" subcommand.
// Keep in sync with the identical map in pkg/brutus/creds/creds.go.
var httpProtocols = map[string]bool{
	"http":    true,
	"https":   true,
	"browser": true,
}

// IsWebProtocol returns true for http, https, and browser protocols.
func IsWebProtocol(protocol string) bool {
	return httpProtocols[protocol]
}
