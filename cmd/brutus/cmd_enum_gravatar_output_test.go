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

	"github.com/praetorian-inc/brutus/pkg/enum/gravatar"
)

// ---------------------------------------------------------------------------
// outputGravatarEnumJSONL — First/Last name propagation (10T-535)
// ---------------------------------------------------------------------------

// TestOutputGravatarEnumJSONL_NameFields pins the never-invent-a-name rule: a
// Result carrying First/Last (from --generate) must emit "first"/"last" in
// the JSONL row, while a Result with empty First/Last (supplied via
// --emails or --email-file) must OMIT both keys entirely rather than emit
// them as "". Pre-existing fields (email/hash/exists/avatar_url) must be
// unaffected.
func TestOutputGravatarEnumJSONL_NameFields(t *testing.T) {
	named := gravatar.Result{
		Email:  "john.smith@example.com",
		Hash:   gravatar.HashEmail("john.smith@example.com"),
		Exists: true,
		First:  "john",
		Last:   "smith",
	}
	unnamed := gravatar.Result{
		Email:  "supplied@example.com",
		Hash:   gravatar.HashEmail("supplied@example.com"),
		Exists: true,
	}

	t.Run("named result emits first and last", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{named})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGravatarEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.Equal(t, "john", obj["first"], `first field must be "john"`)
		assert.Equal(t, "smith", obj["last"], `last field must be "smith"`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, named.Email, obj["email"])
		assert.Equal(t, named.Hash, obj["hash"])
		assert.Equal(t, true, obj["exists"])
		assert.Contains(t, obj["avatar_url"], named.Hash)
	})

	t.Run("unnamed result omits first and last keys", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{unnamed})

		line := strings.TrimSpace(buf.String())
		require.NotEmpty(t, line, "outputGravatarEnumJSONL must produce a JSONL line")

		var obj map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(line), &obj),
			"JSONL output must be valid JSON: %q", line)

		assert.NotContains(t, obj, "first",
			`first key must be absent (omitempty), not emitted as ""`)
		assert.NotContains(t, obj, "last",
			`last key must be absent (omitempty), not emitted as ""`)

		// Pre-existing fields must remain unaffected.
		assert.Equal(t, unnamed.Email, obj["email"])
		assert.Equal(t, unnamed.Hash, obj["hash"])
		assert.Equal(t, true, obj["exists"])
	})

	t.Run("mixed batch: one named, one unnamed", func(t *testing.T) {
		var buf bytes.Buffer
		outputGravatarEnumJSONL(&buf, []gravatar.Result{named, unnamed})

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
