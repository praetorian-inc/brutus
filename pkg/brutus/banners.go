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

// isHTTPProtocol returns true if the protocol uses HTTP Basic Auth
// and can benefit from LLM-based application detection.
func isHTTPProtocol(protocol string) bool {
	switch protocol {
	case "http", "https", "couchdb", "elasticsearch", "influxdb":
		return true
	default:
		return false
	}
}
