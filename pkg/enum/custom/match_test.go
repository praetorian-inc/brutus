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
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// newParsedSpec is a helper that builds and validates a Spec from JSON bytes,
// fatally failing the test if either step errors.
func newParsedSpec(t *testing.T, data []byte) *Spec {
	t.Helper()
	spec, err := Parse(data)
	require.NoError(t, err, "Parse failed")
	require.NoError(t, spec.Validate(), "Validate failed")
	return spec
}

// ---------------------------------------------------------------------------
// T3: evaluate — status condition, first-match ordering, default
// ---------------------------------------------------------------------------

// TestEvaluate_Status verifies that a status-only rule fires correctly for
// scalar match, list match, ordering, and the default fallback.
func TestEvaluate_Status(t *testing.T) {
	t.Parallel()
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "status-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{"when": {"status": 200}, "verdict": "exists",  "confidence": "high"},
					{"when": {"status": 404}, "verdict": "absent",  "confidence": "high"}
				],
				"default": "error"
			}
		}
	}`))

	tests := []struct {
		name        string
		in          matchInput
		wantVerdict string
		wantConf    enum.Confidence
	}{
		{
			name:        "200 → exists/high",
			in:          matchInput{status: 200},
			wantVerdict: "exists",
			wantConf:    enum.ConfidenceHigh,
		},
		{
			name:        "404 → absent/high",
			in:          matchInput{status: 404},
			wantVerdict: "absent",
			wantConf:    enum.ConfidenceHigh,
		},
		{
			name:        "500 → default error/low",
			in:          matchInput{status: 500},
			wantVerdict: "error",
			wantConf:    enum.ConfidenceLow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verdict, conf := spec.evaluate(tc.in)
			assert.Equal(t, tc.wantVerdict, verdict)
			assert.Equal(t, tc.wantConf, conf)
		})
	}
}

// TestEvaluate_StatusList verifies that a rule with a status list fires when
// the response status is any element of the list.
func TestEvaluate_StatusList(t *testing.T) {
	t.Parallel()
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "status-list-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{"when": {"status": [200, 201, 204]}, "verdict": "exists", "confidence": "high"}
				],
				"default": "absent"
			}
		}
	}`))

	for _, status := range []int{200, 201, 204} {
		t.Run("status matches in list", func(t *testing.T) {
			t.Parallel()
			verdict, conf := spec.evaluate(matchInput{status: status})
			assert.Equal(t, "exists", verdict)
			assert.Equal(t, enum.ConfidenceHigh, conf)
		})
	}

	t.Run("status not in list falls to default", func(t *testing.T) {
		t.Parallel()
		verdict, conf := spec.evaluate(matchInput{status: 403})
		assert.Equal(t, "absent", verdict)
		assert.Equal(t, enum.ConfidenceLow, conf)
	})
}

// TestEvaluate_FirstMatchOrdering verifies that the first matching rule wins,
// even when a later rule would also match.
func TestEvaluate_FirstMatchOrdering(t *testing.T) {
	t.Parallel()
	// Both rules match 200; first one should win.
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "ordering-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{"when": {"status": 200}, "verdict": "exists",  "confidence": "high"},
					{"when": {"status": 200}, "verdict": "absent",  "confidence": "low"}
				],
				"default": "error"
			}
		}
	}`))

	verdict, conf := spec.evaluate(matchInput{status: 200})
	assert.Equal(t, "exists", verdict, "first matching rule must win")
	assert.Equal(t, enum.ConfidenceHigh, conf)
}

// ---------------------------------------------------------------------------
// T4: evaluate — body_contains and body_regex
// ---------------------------------------------------------------------------

// TestEvaluate_BodyContains verifies that body_contains triggers only when
// the substring is present in the response body.
func TestEvaluate_BodyContains(t *testing.T) {
	t.Parallel()
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "body-contains-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{"when": {"body_contains": "reset link sent"}, "verdict": "exists", "confidence": "high"}
				],
				"default": "absent"
			}
		}
	}`))

	t.Run("substring present → exists/high", func(t *testing.T) {
		t.Parallel()
		verdict, conf := spec.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"message": "reset link sent to your email"}`),
		})
		assert.Equal(t, "exists", verdict)
		assert.Equal(t, enum.ConfidenceHigh, conf)
	})

	t.Run("substring absent → default absent", func(t *testing.T) {
		t.Parallel()
		verdict, conf := spec.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"message": "user not found"}`),
		})
		assert.Equal(t, "absent", verdict)
		assert.Equal(t, enum.ConfidenceLow, conf)
	})
}

// TestEvaluate_BodyRegex verifies that body_regex uses the precompiled RE2
// regexp and fires correctly.
func TestEvaluate_BodyRegex(t *testing.T) {
	t.Parallel()
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "body-regex-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{"when": {"body_regex": "(?i)user not found"}, "verdict": "absent", "confidence": "medium"}
				],
				"default": "error"
			}
		}
	}`))

	t.Run("regex matches (case-insensitive) → absent/medium", func(t *testing.T) {
		t.Parallel()
		verdict, conf := spec.evaluate(matchInput{
			status: 404,
			body:   []byte(`USER NOT FOUND`),
		})
		assert.Equal(t, "absent", verdict)
		assert.Equal(t, enum.ConfidenceMedium, conf)
	})

	t.Run("regex does not match → default error", func(t *testing.T) {
		t.Parallel()
		verdict, conf := spec.evaluate(matchInput{
			status: 404,
			body:   []byte(`Account deleted`),
		})
		assert.Equal(t, "error", verdict)
		assert.Equal(t, enum.ConfidenceLow, conf)
	})
}

// TestEvaluate_StatusAndBodyAND verifies that when a rule has both status and
// body_contains, BOTH must be true for the rule to fire.
func TestEvaluate_StatusAndBodyAND(t *testing.T) {
	t.Parallel()
	spec := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "and-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{
						"when": {"status": 200, "body_contains": "reset link sent"},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "absent"
			}
		}
	}`))

	tests := []struct {
		name        string
		in          matchInput
		wantVerdict string
	}{
		{
			name:        "status=200 + body has substring → exists",
			in:          matchInput{status: 200, body: []byte("reset link sent to you")},
			wantVerdict: "exists",
		},
		{
			name:        "status=200 but body missing → default absent",
			in:          matchInput{status: 200, body: []byte("something else")},
			wantVerdict: "absent",
		},
		{
			name:        "body has substring but status=404 → default absent",
			in:          matchInput{status: 404, body: []byte("reset link sent to you")},
			wantVerdict: "absent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verdict, _ := spec.evaluate(tc.in)
			assert.Equal(t, tc.wantVerdict, verdict)
		})
	}
}

// ---------------------------------------------------------------------------
// T5: evaluate — json_field (path + equals/in)
// ---------------------------------------------------------------------------

// TestEvaluate_JSONField verifies json_field matching including nested path,
// "in" set, missing path → false, and non-JSON body → false.
func TestEvaluate_JSONField(t *testing.T) {
	t.Parallel()

	// Microsoft 365-style oracle: IfExistsResult ∈ {0,5,6} → exists
	specM365 := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "m365-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{
						"when": {"json_field": {"path": "IfExistsResult", "in": ["0", "5", "6"]}},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "absent"
			}
		}
	}`))

	t.Run("IfExistsResult=0 → exists (in set)", func(t *testing.T) {
		t.Parallel()
		verdict, conf := specM365.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"IfExistsResult":0}`),
		})
		assert.Equal(t, "exists", verdict)
		assert.Equal(t, enum.ConfidenceHigh, conf)
	})

	t.Run("IfExistsResult=5 → exists (in set)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specM365.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"IfExistsResult":5}`),
		})
		assert.Equal(t, "exists", verdict)
	})

	t.Run("IfExistsResult=6 → exists (in set)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specM365.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"IfExistsResult":6}`),
		})
		assert.Equal(t, "exists", verdict)
	})

	t.Run("IfExistsResult=1 → absent (not in set → default)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specM365.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"IfExistsResult":1}`),
		})
		assert.Equal(t, "absent", verdict)
	})

	// Nested path test: data.exists == "true"
	specNested := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "nested-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{
						"when": {"json_field": {"path": "data.exists", "equals": "true"}},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "absent"
			}
		}
	}`))

	t.Run("nested path data.exists=true → exists", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specNested.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"data":{"exists":true}}`),
		})
		assert.Equal(t, "exists", verdict)
	})

	t.Run("nested path data.exists=false → absent (default)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specNested.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"data":{"exists":false}}`),
		})
		assert.Equal(t, "absent", verdict)
	})

	t.Run("missing path → condition false (falls to default)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specNested.evaluate(matchInput{
			status: 200,
			body:   []byte(`{"data":{}}`),
		})
		assert.Equal(t, "absent", verdict)
	})

	t.Run("non-JSON body → condition false (R7/R11)", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specNested.evaluate(matchInput{
			status: 200,
			body:   []byte(`not json at all`),
		})
		assert.Equal(t, "absent", verdict)
	})
}

// ---------------------------------------------------------------------------
// T6: evaluate — header (present + equals)
// ---------------------------------------------------------------------------

// TestEvaluate_Header verifies header matching with present=true, equals, and
// missing header cases.
func TestEvaluate_Header(t *testing.T) {
	t.Parallel()

	specPresent := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "header-present-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{
						"when": {"header": {"name": "X-Account", "present": true}},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "absent"
			}
		}
	}`))

	t.Run("header present → exists/high", func(t *testing.T) {
		t.Parallel()
		h := http.Header{}
		h.Set("X-Account", "yes")
		verdict, conf := specPresent.evaluate(matchInput{status: 200, header: h})
		assert.Equal(t, "exists", verdict)
		assert.Equal(t, enum.ConfidenceHigh, conf)
	})

	t.Run("header absent → default absent", func(t *testing.T) {
		t.Parallel()
		verdict, _ := specPresent.evaluate(matchInput{status: 200, header: http.Header{}})
		assert.Equal(t, "absent", verdict)
	})

	equalsVal := "yes"
	specEquals := newParsedSpec(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "header-equals-test",
			"request": {"method": "POST", "url": "https://example.com"},
			"match": {
				"rules": [
					{
						"when": {"header": {"name": "X-Account", "equals": "yes"}},
						"verdict": "exists",
						"confidence": "high"
					}
				],
				"default": "absent"
			}
		}
	}`))
	_ = equalsVal

	t.Run("header equals match → exists", func(t *testing.T) {
		t.Parallel()
		h := http.Header{}
		h.Set("X-Account", "yes")
		verdict, _ := specEquals.evaluate(matchInput{status: 200, header: h})
		assert.Equal(t, "exists", verdict)
	})

	t.Run("header equals mismatch → absent", func(t *testing.T) {
		t.Parallel()
		h := http.Header{}
		h.Set("X-Account", "no")
		verdict, _ := specEquals.evaluate(matchInput{status: 200, header: h})
		assert.Equal(t, "absent", verdict)
	})

	t.Run("case-insensitive via http.Header.Get", func(t *testing.T) {
		t.Parallel()
		h := http.Header{}
		h.Set("x-account", "yes") // lowercase set, matched case-insensitively
		verdict, _ := specPresent.evaluate(matchInput{status: 200, header: h})
		assert.Equal(t, "exists", verdict)
	})

	// present-but-empty-valued header must count as present (fix: Values() > 0).
	t.Run("header present with empty value → exists (empty value still present)", func(t *testing.T) {
		t.Parallel()
		h := http.Header{}
		h.Set("X-Account", "")
		verdict, conf := specPresent.evaluate(matchInput{status: 200, header: h})
		assert.Equal(t, "exists", verdict,
			"a header set to an empty string is still present (len(Values())>0)")
		assert.Equal(t, enum.ConfidenceHigh, conf)
	})

	t.Run("header truly absent → default absent", func(t *testing.T) {
		t.Parallel()
		// No X-Account header set at all.
		verdict, _ := specPresent.evaluate(matchInput{status: 200, header: http.Header{}})
		assert.Equal(t, "absent", verdict,
			"a header that was never set must not count as present")
	})
}

// ---------------------------------------------------------------------------
// T7: applyVerdict + errInconclusive (R7 no-body-in-error)
// ---------------------------------------------------------------------------

// TestApplyVerdict verifies the verdict-to-result mapping for all three
// verdicts, and specifically that the "error" verdict message contains only
// status information and never embeds the response body (R7).
func TestApplyVerdict(t *testing.T) {
	t.Parallel()

	t.Run("exists → Exists=true, Error=nil", func(t *testing.T) {
		t.Parallel()
		result := &enum.Result{}
		applyVerdict(result, "exists", enum.ConfidenceHigh, 200)
		assert.True(t, result.Exists)
		assert.Nil(t, result.Error)
		assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
	})

	t.Run("absent → Exists=false, Error=nil", func(t *testing.T) {
		t.Parallel()
		result := &enum.Result{}
		applyVerdict(result, "absent", enum.ConfidenceMedium, 404)
		assert.False(t, result.Exists)
		assert.Nil(t, result.Error)
		assert.Equal(t, enum.ConfidenceMedium, result.Confidence)
	})

	t.Run("error → errInconclusive sentinel, Exists=false", func(t *testing.T) {
		t.Parallel()
		result := &enum.Result{}
		applyVerdict(result, "error", enum.ConfidenceLow, 500)
		assert.False(t, result.Exists)
		require.Error(t, result.Error)
		assert.True(t, errors.Is(result.Error, errInconclusive),
			"error verdict must use errInconclusive sentinel; got: %v", result.Error)
	})

	// R7: error message must contain status but must NOT contain body content.
	t.Run("R7 error message contains status but not body content", func(t *testing.T) {
		t.Parallel()
		result := &enum.Result{}
		applyVerdict(result, "error", enum.ConfidenceLow, 503)
		require.Error(t, result.Error)
		msg := result.Error.Error()
		assert.Contains(t, msg, "status=503",
			"error message must include HTTP status code")
		// The body of the response is never included (R7).
		// We verify by checking that error message is short and structured.
		assert.NotContains(t, msg, "<html", "body content must not appear in error message")
		assert.NotContains(t, msg, "Internal Server Error", "body content must not appear in error message")
	})
}
