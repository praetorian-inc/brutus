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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// masscanEntry represents a single host entry in masscan JSON output (-oJ).
type masscanEntry struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

// masscanPort represents a single port within a masscan entry.
type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// LoadMasscanFile parses a masscan JSON file (-oJ output) and returns a
// slice of NervaResult for each open port. Because masscan does not perform
// service fingerprinting, the Protocol field is left empty — callers must
// either require --protocol or run Nerva fingerprinting on the returned
// targets.
func LoadMasscanFile(filePath string) ([]NervaResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening masscan file: %w", err)
	}

	// Normalize masscan's quirky JSON: strip the trailing comma before the
	// closing ']'. Masscan emits a comma after every entry including the last
	// one, producing e.g. `[{...}, {...}, ]`. We only fix this structural
	// artifact at the end of the array rather than applying a global regex
	// that could corrupt string literals containing ", ]" or ", }".
	cleaned := stripTrailingComma(data)

	var entries []masscanEntry
	if err := json.Unmarshal(cleaned, &entries); err != nil {
		return nil, fmt.Errorf("parsing masscan JSON: %w", err)
	}

	var results []NervaResult
	for _, entry := range entries {
		for _, port := range entry.Ports {
			if port.Status != "open" {
				continue
			}

			results = append(results, NervaResult{
				IP:        entry.IP,
				Port:      port.Port,
				Protocol:  "", // masscan does not fingerprint services
				Transport: port.Proto,
			})
		}
	}

	return results, nil
}

// stripTrailingComma removes the last comma before the closing ']' of a
// JSON array. This is the only structural fix masscan output needs — the
// last entry is followed by a comma before ']'. Operating only on the
// trailing position avoids corrupting commas inside string values.
func stripTrailingComma(data []byte) []byte {
	// Find the last ']' (top-level array close).
	idx := bytes.LastIndexByte(data, ']')
	if idx < 0 {
		return data
	}

	// Walk backwards from ']' skipping whitespace to find a comma.
	i := idx - 1
	for i >= 0 && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i--
	}
	if i >= 0 && data[i] == ',' {
		// Remove the comma by splicing it out.
		out := make([]byte, 0, len(data)-1)
		out = append(out, data[:i]...)
		out = append(out, data[i+1:]...)
		return out
	}
	return data
}
