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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// outputEnumJSONL — First/Last name propagation (10T-535)
// ---------------------------------------------------------------------------

// TestOutputEnumJSONL_NameFields pins the never-invent-a-name rule for the
// generic enum output path: a Result carrying First/Last (from --generate)
// must emit "first"/"last" in the JSONL row, while a Result with empty
// First/Last (supplied via --emails or --email-file) must OMIT both keys
// entirely rather than emit them as "". Pre-existing fields
// (type/service/email/exists/confidence) must be unaffected.
func TestOutputEnumJSONL_NameFields(t *testing.T) {
	named := enum.Result{
		Service:    "github",
		Email:      "john.smith@example.com",
		First:      "john",
		Last:       "smith",
		Exists:     true,
		Confidence: enum.ConfidenceHigh,
	}
	unnamed := enum.Result{
		Service:    "github",
		Email:      "supplied@example.com",
		Exists:     false,
		Confidence: enum.ConfidenceLow,
	}

	t.Run("named result emits first and last", func(t *testing.T) {
		var buf bytes.Buffer
		outputEnumJSONL(&buf, []enum.Result{named})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.Equal(t, "john", obj["first"], `first field must be "john"`)
		assert.Equal(t, "smith", obj["last"], `last field must be "smith"`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, "enum", obj["type"])
		assert.Equal(t, "github", obj["service"])
		assert.Equal(t, named.Email, obj["email"])
		assert.Equal(t, true, obj["exists"])
		assert.Equal(t, string(enum.ConfidenceHigh), obj["confidence"])
	})

	t.Run("unnamed result omits first and last keys", func(t *testing.T) {
		var buf bytes.Buffer
		outputEnumJSONL(&buf, []enum.Result{unnamed})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.NotContains(t, obj, "first",
			`first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last",
			`last key must be absent (omitempty), not emitted as ""`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, "enum", obj["type"])
		assert.Equal(t, "github", obj["service"])
		assert.Equal(t, unnamed.Email, obj["email"])
		assert.Equal(t, false, obj["exists"])
		assert.Equal(t, string(enum.ConfidenceLow), obj["confidence"])
	})

	t.Run("mixed batch: one named, one unnamed", func(t *testing.T) {
		var buf bytes.Buffer
		outputEnumJSONL(&buf, []enum.Result{named, unnamed})

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 2, "must emit exactly one JSONL line per result")

		var first map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
		assert.Equal(t, "john", first["first"])
		assert.Equal(t, "smith", first["last"])

		var second map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
		assert.NotContains(t, second, "first")
		assert.NotContains(t, second, "last")
	})
}
