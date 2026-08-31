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

package clisurface

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// jsonDoc is the on-disk shape of docs/cli-surface.json. Field order here is
// the key order in the rendered file.
type jsonDoc struct {
	SchemaVersion int       `json:"schemaVersion"`
	SurfaceHash   string    `json:"surfaceHash"`
	Commands      []Command `json:"commands"`
}

// RenderJSON renders the machine-readable artifact: two-space indentation, no
// HTML escaping, one trailing newline. Key order comes from the struct
// definitions, so the output is byte-stable for a given surface.
func RenderJSON(s Surface) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonDoc{
		SchemaVersion: SchemaVersion,
		SurfaceHash:   s.Hash(),
		Commands:      s.Commands,
	}); err != nil {
		return nil, fmt.Errorf("rendering cli surface json: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseJSON reads a surface back out of the machine-readable artifact.
func ParseJSON(b []byte) (Surface, error) {
	var doc jsonDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return Surface{}, fmt.Errorf("parsing cli surface json: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return Surface{}, fmt.Errorf("cli surface json has schemaVersion %d, this build renders %d: regenerate with 'make cli-docs'",
			doc.SchemaVersion, SchemaVersion)
	}
	// The hash has to describe the commands it ships with, or a hand-edited artifact
	// passes every later comparison: downstream consumers pin the hash, so one that
	// does not match its own contents is worse than a missing one.
	s := Surface{Commands: doc.Commands}
	if got := s.Hash(); doc.SurfaceHash != got {
		return Surface{}, fmt.Errorf("cli surface json records surfaceHash %s but its commands hash to %s: it looks hand-edited, regenerate with '%s'",
			doc.SurfaceHash, got, RegenerateCommand)
	}
	return s, nil
}
