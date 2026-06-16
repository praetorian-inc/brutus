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

package custom

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validSpecJSON returns a minimal valid schema v1 JSON spec for reuse in tests.
func validSpecJSON() []byte {
	return []byte(`{
		"version": "1",
		"oracle": {
			"name": "test-oracle",
			"request": {
				"method": "POST",
				"url": "https://example.com/api"
			},
			"match": {
				"rules": [
					{
						"when": {"status": 200},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "error"
			}
		}
	}`)
}

// validSpecYAML returns a minimal valid schema v1 YAML spec including comments.
func validSpecYAML() []byte {
	return []byte(`# This is a test oracle
version: "1"
oracle:
  name: test-oracle
  request:
    method: POST
    url: https://example.com/api
  match:
    rules:
      - when:
          status: 200
        verdict: exists
        confidence: high
    default: error
`)
}

// TestParse_ValidJSON verifies a well-formed JSON spec parses and validates
// without error.
func TestParse_ValidJSON(t *testing.T) {
	t.Parallel()
	spec, err := Parse(validSpecJSON())
	require.NoError(t, err)
	require.NotNil(t, spec)
	assert.Equal(t, "1", spec.Version)
	assert.Equal(t, "test-oracle", spec.Oracle.Name)

	require.NoError(t, spec.Validate())
}

// TestParse_ValidYAML verifies a well-formed YAML spec (with comments) parses
// and validates to the same Spec as the equivalent JSON.
func TestParse_ValidYAML(t *testing.T) {
	t.Parallel()
	spec, err := Parse(validSpecYAML())
	require.NoError(t, err)
	require.NotNil(t, spec)
	assert.Equal(t, "1", spec.Version)
	assert.Equal(t, "test-oracle", spec.Oracle.Name)
	require.NoError(t, spec.Validate())
}

// TestParse_JSONEqualsYAML checks that equivalent JSON and YAML produce the
// same parsed Spec (D2 single-decoder requirement).
func TestParse_JSONEqualsYAML(t *testing.T) {
	t.Parallel()
	jsonSpec, err := Parse(validSpecJSON())
	require.NoError(t, err)
	yamlSpec, err := Parse(validSpecYAML())
	require.NoError(t, err)

	assert.Equal(t, jsonSpec.Version, yamlSpec.Version)
	assert.Equal(t, jsonSpec.Oracle.Name, yamlSpec.Oracle.Name)
	assert.Equal(t, jsonSpec.Oracle.Request.Method, yamlSpec.Oracle.Request.Method)
	assert.Equal(t, jsonSpec.Oracle.Request.URL, yamlSpec.Oracle.Request.URL)
	assert.Equal(t, len(jsonSpec.Oracle.Match.Rules), len(yamlSpec.Oracle.Match.Rules))
}

// ---------------------------------------------------------------------------
// Table-driven invalid-spec tests
// ---------------------------------------------------------------------------

// invalidSpecCase describes a single invalid-spec test.
type invalidSpecCase struct {
	name         string
	data         []byte
	wantParseErr bool   // error must occur in Parse (not Validate)
	wantField    string // expected SpecError.Field (empty = any)
}

// buildInvalidSpecCases returns the ≥14 invalid-spec cases required by plan.md T2.
func buildInvalidSpecCases() []invalidSpecCase {
	// Helper to patch the valid JSON for a specific invalid variant.
	withVersion := func(v string) []byte {
		return []byte(`{"version":"` + v + `","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}
	withURL := func(url string) []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"` + url + `"},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}
	withEncoding := func(enc string) []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com","body_encoding":"` + enc + `"},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}
	withNoRules := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[],"default":"error"}}}`)
	}
	withBadVerdict := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"status":200},"verdict":"maybe"}],"default":"error"}}}`)
	}
	withEmptyWhen := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{},"verdict":"exists"}],"default":"error"}}}`)
	}
	withBadRegex := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"body_regex":"(?P<invalid"},"verdict":"exists"}],"default":"error"}}}`)
	}
	withLongRegex := func() []byte {
		// 1025 bytes pattern — exceeds the 1024-byte limit (R5)
		longPattern := strings.Repeat("a", 1025)
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"body_regex":"` + longPattern + `"},"verdict":"exists"}],"default":"error"}}}`)
	}
	withJSONFieldBothEqualsAndIn := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"json_field":{"path":"foo","equals":"bar","in":["bar"]}},"verdict":"exists"}],"default":"error"}}}`)
	}
	withJSONFieldBadPath := func() []byte {
		// Path contains '$' which is a JSONPath char — rejected (R11)
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"json_field":{"path":"$.foo","equals":"bar"}},"verdict":"exists"}],"default":"error"}}}`)
	}
	withBadHeaderName := func() []byte {
		// Header name with illegal char (space) — rejected (R1)
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com","headers":{"Bad Name":"value"}},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}
	withLargeStatusArray := func() []byte {
		// Build status array with 65 entries (exceeds limit of 64)
		statuses := make([]string, 65)
		for i := range statuses {
			statuses[i] = "200"
		}
		statusJSON := "[" + strings.Join(statuses, ",") + "]"
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"status":` + statusJSON + `},"verdict":"exists"}],"default":"error"}}}`)
	}
	withTooManyRules := func() []byte {
		// Build 101 rules (exceeds R9 limit of 100)
		var rules []string
		for i := 0; i < 101; i++ {
			rules = append(rules, `{"when":{"status":200},"verdict":"exists"}`)
		}
		rulesJSON := "[" + strings.Join(rules, ",") + "]"
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com"},"match":{"rules":` + rulesJSON + `,"default":"error"}}}`)
	}
	withTooManyHeaders := func() []byte {
		// Build 65 headers (exceeds R9 limit of 64)
		var headerParts []string
		for i := 0; i < 65; i++ {
			headerParts = append(headerParts, `"X-Header-`+string(rune('A'+i%26))+`-`+string(rune('0'+i%10))+`":"value"`)
		}
		headersJSON := "{" + strings.Join(headerParts, ",") + "}"
		return []byte(`{"version":"1","oracle":{"name":"x","request":{"method":"POST","url":"https://example.com","headers":` + headersJSON + `},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}
	withEmptyName := func() []byte {
		return []byte(`{"version":"1","oracle":{"name":"","request":{"method":"POST","url":"https://example.com"},"match":{"rules":[{"when":{"status":200},"verdict":"exists"}],"default":"error"}}}`)
	}

	return []invalidSpecCase{
		{
			name:      "bad version",
			data:      withVersion("2"),
			wantField: "version",
		},
		{
			name:      "empty oracle name",
			data:      withEmptyName(),
			wantField: "oracle.name",
		},
		{
			name:      "file:// URL scheme rejected (P0-5 / R4)",
			data:      withURL("file:///etc/passwd"),
			wantField: "oracle.request.url",
		},
		{
			name:      "gopher:// URL scheme rejected (P0-5 / R4)",
			data:      withURL("gopher://evil.example.com"),
			wantField: "oracle.request.url",
		},
		{
			name:      "unknown body_encoding rejected",
			data:      withEncoding("binary"),
			wantField: "oracle.request.body_encoding",
		},
		{
			name:      "empty rules list rejected",
			data:      withNoRules(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "rules count >100 rejected (R9)",
			data:      withTooManyRules(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "bad verdict rejected",
			data:      withBadVerdict(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "empty when rejected (every condition inactive)",
			data:      withEmptyWhen(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "uncompilable body_regex rejected (R5)",
			data:      withBadRegex(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "body_regex >1024 bytes rejected (R5)",
			data:      withLongRegex(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "json_field with both equals and in rejected",
			data:      withJSONFieldBothEqualsAndIn(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "json_field path with JSONPath char '$' rejected (R11)",
			data:      withJSONFieldBadPath(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "header name with illegal char rejected (R1)",
			data:      withBadHeaderName(),
			wantField: "oracle.request.headers",
		},
		{
			name:      "status array >64 elements rejected (R9)",
			data:      withLargeStatusArray(),
			wantField: "oracle.match.rules",
		},
		{
			name:      "too many headers >64 rejected (R9)",
			data:      withTooManyHeaders(),
			wantField: "oracle.request.headers",
		},
	}
}

// TestParse_InvalidSpecs is the main table-driven test covering ≥14 invalid
// spec cases as required by plan.md T2.  Each case must produce a *SpecError
// (or parse error for structural failures) with a non-empty message.
func TestParse_InvalidSpecs(t *testing.T) {
	t.Parallel()
	cases := buildInvalidSpecCases()
	// Verify we meet the plan's requirement for ≥14 cases.
	assert.GreaterOrEqual(t, len(cases), 14, "plan.md requires ≥14 invalid-spec test cases")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.wantParseErr {
				// The error must occur in Parse itself.
				_, err := Parse(tc.data)
				require.Error(t, err, "Parse must return an error for: %s", tc.name)
				return
			}

			// For validation errors: Parse may succeed, Validate must fail.
			spec, parseErr := Parse(tc.data)
			if parseErr != nil {
				// Parse error is also acceptable for these cases.
				assert.Contains(t, parseErr.Error(), tc.wantField,
					"parse error should mention field %q", tc.wantField)
				return
			}
			require.NotNil(t, spec)

			validateErr := spec.Validate()
			require.Error(t, validateErr, "Validate must return an error for: %s", tc.name)

			// The error must be a *SpecError and mention the expected field.
			var specErr *SpecError
			if assert.ErrorAs(t, validateErr, &specErr, "error must be *SpecError for case: %s", tc.name) {
				if tc.wantField != "" {
					assert.Equal(t, tc.wantField, specErr.Field,
						"SpecError.Field mismatch for case: %s", tc.name)
				}
			}
		})
	}
}

// TestParse_KnownFields verifies that a spec with an unknown top-level key is
// rejected by Parse (plan.md T2 / R8 / P0-7 — KnownFields(true)).
func TestParse_KnownFields(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "x",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		},
		"unknown_key_that_does_not_exist": "should cause error"
	}`)

	_, err := Parse(data)
	require.Error(t, err, "Parse must reject unknown top-level keys (KnownFields=true)")
}

// TestParse_KnownFields_NestedUnknown verifies KnownFields rejects unknown
// nested keys too (e.g. inside oracle.request).
func TestParse_KnownFields_NestedUnknown(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "x",
			"request": {
				"method": "POST",
				"url": "https://example.com",
				"unknown_request_field": "bad"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`)

	_, err := Parse(data)
	require.Error(t, err, "Parse must reject unknown nested keys (KnownFields=true)")
}

// TestValidate_CompilesRegexes verifies that after a successful Validate(),
// the compiledRe slice is populated for rules with body_regex.
func TestValidate_CompilesRegexes(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "regex-oracle",
			"request": {"method": "POST", "url": "https://example.com/api"},
			"match": {
				"rules": [
					{"when": {"body_regex": "(?i)user not found"}, "verdict": "absent", "confidence": "medium"},
					{"when": {"status": 200}, "verdict": "exists", "confidence": "high"}
				],
				"default": "error"
			}
		}
	}`)

	spec, err := Parse(data)
	require.NoError(t, err)
	require.NoError(t, spec.Validate())

	require.Len(t, spec.compiledRe, 2)
	require.NotNil(t, spec.compiledRe[0], "rule with body_regex should be compiled")
	assert.Nil(t, spec.compiledRe[1], "rule without body_regex should remain nil")
}

// TestValidate_DefaultError verifies that the default "error" verdict is
// accepted and that an empty default defaults to "error".
func TestValidate_DefaultError(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "x",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}]
			}
		}
	}`)

	spec, err := Parse(data)
	require.NoError(t, err)
	require.NoError(t, spec.Validate())
	// After Validate, default should be normalised to "error" (empty → "error")
	assert.Equal(t, "error", spec.Oracle.Match.Default)
}

// TestSpecError_Format verifies SpecError.Error() has the expected format.
func TestSpecError_Format(t *testing.T) {
	t.Parallel()
	se := &SpecError{Field: "oracle.request.url", Reason: "unsupported scheme: file"}
	msg := se.Error()
	assert.Contains(t, msg, "oracle spec invalid")
	assert.Contains(t, msg, "oracle.request.url")
	assert.Contains(t, msg, "unsupported scheme")
}
