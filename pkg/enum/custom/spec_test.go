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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSpec_JSONRoundTrip verifies that a minimal schema v1 document can be
// unmarshalled into a Spec and that top-level fields are preserved correctly.
func TestSpec_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "x",
			"request": {
				"method": "POST",
				"url": "https://h/p"
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

	var s Spec
	require.NoError(t, json.Unmarshal(data, &s))
	assert.Equal(t, "1", s.Version)
	assert.Equal(t, "x", s.Oracle.Name)
	assert.Equal(t, "POST", s.Oracle.Request.Method)
	assert.Equal(t, "https://h/p", s.Oracle.Request.URL)
	require.Len(t, s.Oracle.Match.Rules, 1)
	assert.Equal(t, "error", s.Oracle.Match.Default)
	assert.Equal(t, "exists", s.Oracle.Match.Rules[0].Verdict)
	assert.Equal(t, "high", s.Oracle.Match.Rules[0].Confidence)
	require.NotNil(t, s.Oracle.Match.Rules[0].When.Status)
	assert.Equal(t, []int{200}, s.Oracle.Match.Rules[0].When.Status.Values())
}

// TestStatusMatch_ScalarAndList verifies that StatusMatch accepts both a single
// integer (scalar) and a JSON array of integers and normalises both to []int.
func TestStatusMatch_ScalarAndList(t *testing.T) {
	t.Parallel()

	t.Run("scalar 200 → []int{200}", func(t *testing.T) {
		t.Parallel()
		data := []byte(`200`)
		var sm StatusMatch
		require.NoError(t, json.Unmarshal(data, &sm))
		assert.Equal(t, []int{200}, sm.Values())
	})

	t.Run("list [200,404] → []int{200,404}", func(t *testing.T) {
		t.Parallel()
		data := []byte(`[200, 404]`)
		var sm StatusMatch
		require.NoError(t, json.Unmarshal(data, &sm))
		assert.Equal(t, []int{200, 404}, sm.Values())
	})

	t.Run("scalar embedded in rule When struct", func(t *testing.T) {
		t.Parallel()
		data := []byte(`{"status": 404}`)
		var w When
		require.NoError(t, json.Unmarshal(data, &w))
		require.NotNil(t, w.Status)
		assert.Equal(t, []int{404}, w.Status.Values())
	})

	t.Run("list embedded in rule When struct", func(t *testing.T) {
		t.Parallel()
		data := []byte(`{"status": [200, 201, 204]}`)
		var w When
		require.NoError(t, json.Unmarshal(data, &w))
		require.NotNil(t, w.Status)
		assert.Equal(t, []int{200, 201, 204}, w.Status.Values())
	})
}

// TestSpec_FullTypes verifies that all schema v1 types round-trip through JSON
// and that optional/pointer fields are handled correctly.
func TestSpec_FullTypes(t *testing.T) {
	t.Parallel()
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "forgotpassword",
			"request": {
				"method": "POST",
				"url": "https://example.com/forgot",
				"headers": {"Content-Type": "application/json"},
				"body": "{\"username\":\"{{username}}\"}",
				"body_encoding": "json"
			},
			"match": {
				"rules": [
					{
						"when": {
							"status": 200,
							"body_contains": "reset link sent"
						},
						"verdict": "exists",
						"confidence": "high"
					},
					{
						"when": {"status": 404},
						"verdict": "absent",
						"confidence": "high"
					},
					{
						"when": {"body_regex": "(?i)user not found"},
						"verdict": "absent",
						"confidence": "medium"
					},
					{
						"when": {
							"json_field": {
								"path": "data.exists",
								"equals": "true"
							}
						},
						"verdict": "exists",
						"confidence": "high"
					},
					{
						"when": {
							"header": {
								"name": "X-Account",
								"present": true
							}
						},
						"verdict": "exists",
						"confidence": "medium"
					}
				],
				"default": "error"
			}
		},
		"constraints": {
			"rate_limit_rps": 5.0,
			"lockout": false,
			"captcha": true
		}
	}`)

	var s Spec
	require.NoError(t, json.Unmarshal(data, &s))

	assert.Equal(t, "1", s.Version)
	assert.Equal(t, "forgotpassword", s.Oracle.Name)
	assert.Equal(t, "POST", s.Oracle.Request.Method)
	assert.Equal(t, "application/json", s.Oracle.Request.Headers["Content-Type"])
	assert.Equal(t, "json", s.Oracle.Request.BodyEncoding)
	require.Len(t, s.Oracle.Match.Rules, 5)

	// Rule 0: status + body_contains
	r0 := s.Oracle.Match.Rules[0]
	require.NotNil(t, r0.When.Status)
	assert.Equal(t, []int{200}, r0.When.Status.Values())
	assert.Equal(t, "reset link sent", r0.When.BodyContains)
	assert.Equal(t, "exists", r0.Verdict)
	assert.Equal(t, "high", r0.Confidence)

	// Rule 2: body_regex
	r2 := s.Oracle.Match.Rules[2]
	assert.Equal(t, "(?i)user not found", r2.When.BodyRegex)
	assert.Equal(t, "absent", r2.Verdict)
	assert.Equal(t, "medium", r2.Confidence)

	// Rule 3: json_field equals
	r3 := s.Oracle.Match.Rules[3]
	require.NotNil(t, r3.When.JSONField)
	assert.Equal(t, "data.exists", r3.When.JSONField.Path)
	require.NotNil(t, r3.When.JSONField.Equals)
	assert.Equal(t, "true", *r3.When.JSONField.Equals)

	// Rule 4: header present
	r4 := s.Oracle.Match.Rules[4]
	require.NotNil(t, r4.When.Header)
	assert.Equal(t, "X-Account", r4.When.Header.Name)
	require.NotNil(t, r4.When.Header.Present)
	assert.True(t, *r4.When.Header.Present)

	// Constraints
	require.NotNil(t, s.Constraints)
	assert.InDelta(t, 5.0, s.Constraints.RateLimitRPS, 0.001)
	assert.False(t, s.Constraints.Lockout)
	assert.True(t, s.Constraints.Captcha)
}

// TestSpec_JSONFieldMatch_InList verifies json_field with "in" list is parsed.
func TestSpec_JSONFieldMatch_InList(t *testing.T) {
	t.Parallel()
	data := []byte(`{"path": "IfExistsResult", "in": ["0", "5", "6"]}`)
	var jfm JSONFieldMatch
	require.NoError(t, json.Unmarshal(data, &jfm))
	assert.Equal(t, "IfExistsResult", jfm.Path)
	assert.Nil(t, jfm.Equals)
	assert.Equal(t, []string{"0", "5", "6"}, jfm.In)
}

// TestSpec_HeaderMatch_Equals verifies HeaderMatch with equals pointer.
func TestSpec_HeaderMatch_Equals(t *testing.T) {
	t.Parallel()
	equalsVal := "yes"
	data := []byte(`{"name": "X-Account", "equals": "yes"}`)
	var hm HeaderMatch
	require.NoError(t, json.Unmarshal(data, &hm))
	assert.Equal(t, "X-Account", hm.Name)
	assert.Nil(t, hm.Present)
	require.NotNil(t, hm.Equals)
	assert.Equal(t, equalsVal, *hm.Equals)
}
