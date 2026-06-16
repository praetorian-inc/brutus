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
	"context"
	"encoding/json"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// T8: derivePlaceholders
// ---------------------------------------------------------------------------

// TestDerivePlaceholders verifies the subject-to-placeholder mapping described
// in architecture.md §7 (D5).
func TestDerivePlaceholders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		subject       string
		wantUsername  string
		wantEmail     string
		wantLocalpart string
		wantDomain    string
	}{
		{
			name:          "email subject",
			subject:       "jsmith@acme.com",
			wantUsername:  "jsmith@acme.com",
			wantEmail:     "jsmith@acme.com",
			wantLocalpart: "jsmith",
			wantDomain:    "acme.com",
		},
		{
			name:          "bare username (no @)",
			subject:       "jsmith",
			wantUsername:  "jsmith",
			wantEmail:     "jsmith",
			wantLocalpart: "jsmith",
			wantDomain:    "",
		},
		{
			name:          "subject with multiple @ signs uses first split",
			subject:       "user@sub@domain.com",
			wantUsername:  "user@sub@domain.com",
			wantEmail:     "user@sub@domain.com",
			wantLocalpart: "user",
			wantDomain:    "sub@domain.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ph := derivePlaceholders(tc.subject)
			assert.Equal(t, tc.wantUsername, ph["username"])
			assert.Equal(t, tc.wantEmail, ph["email"])
			assert.Equal(t, tc.wantLocalpart, ph["localpart"])
			assert.Equal(t, tc.wantDomain, ph["domain"])
		})
	}
}

// ---------------------------------------------------------------------------
// T8: buildRequest — per-sink escaping and rejection tests
// One test per sink × hostile input (the P0 checks).
// ---------------------------------------------------------------------------

// buildSpecForRequest is a helper that creates a parsed, validated Spec from
// raw JSON for request builder tests.
func buildSpecForRequest(t *testing.T, specJSON []byte) *Spec {
	t.Helper()
	spec, err := Parse(specJSON)
	require.NoError(t, err)
	require.NoError(t, spec.Validate())
	return spec
}

// TestBuildRequest_P0_1_HeaderCRLFRejected verifies P0-1 (R1): a subject
// containing CRLF substituted into a header value causes buildRequest to
// return an error and NOT build a request.
func TestBuildRequest_P0_1_HeaderCRLFRejected(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "header-inject-test",
			"request": {
				"method": "GET",
				"url": "https://example.com/api",
				"headers": {
					"X-Username": "{{username}}"
				}
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	// Subject with CRLF injection attempt.
	req, err := buildRequest(spec, context.Background(), "a\r\nX-Injected: 1")
	require.Error(t, err, "buildRequest must reject CRLF in header value (P0-1)")
	assert.Nil(t, req, "no request must be built when header value contains CRLF")
}

// TestBuildRequest_P0_1_ControlByteRejected verifies that bytes < 0x20 in a
// header value are also rejected (not just CR/LF).
func TestBuildRequest_P0_1_ControlByteRejected(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "ctrl-header-test",
			"request": {
				"method": "GET",
				"url": "https://example.com/api",
				"headers": {"X-Tenant": "{{domain}}"}
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	// Subject with a control char in domain position.
	req, err := buildRequest(spec, context.Background(), "user@evil\x01.com")
	require.Error(t, err, "buildRequest must reject control bytes in header value (P0-1)")
	assert.Nil(t, req)
}

// TestBuildRequest_P0_2_JSONBodyInjectionRejected verifies P0-2 (R2): a
// subject containing JSON breakout characters is JSON-string-escaped so that
// the on-wire body is valid JSON and the injected key does NOT appear.
func TestBuildRequest_P0_2_JSONBodyInjectionRejected(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "json-inject-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/api",
				"body": "{\"u\":\"{{username}}\"}",
				"body_encoding": "json"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	// The hostile subject attempts JSON breakout.
	hostileSubject := `a","admin":true,"x":"`
	req, err := buildRequest(spec, context.Background(), hostileSubject)
	require.NoError(t, err, "buildRequest should succeed (escaping, not rejection)")
	require.NotNil(t, req)

	bodyBytes, readErr := io.ReadAll(req.Body)
	require.NoError(t, readErr)

	// On-wire body must be valid JSON.
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed),
		"on-wire body must be valid JSON; got: %s", string(bodyBytes))

	// The injected "admin" key must NOT be present.
	_, hasAdmin := parsed["admin"]
	assert.False(t, hasAdmin, "injected admin key must not appear in JSON body (P0-2)")

	// The "u" key must equal the literal injected string.
	uVal, ok := parsed["u"]
	require.True(t, ok, `"u" key must exist in JSON body`)
	assert.Equal(t, hostileSubject, uVal,
		`"u" value must be the literal subject (JSON-escaped), not broken out`)
}

// TestBuildRequest_P0_3_FormBodyInjectionRejected verifies P0-3 (R2): a
// subject containing `&role=admin` in a form-encoded body has its value
// QueryEscape'd so that no extra parameter appears.
func TestBuildRequest_P0_3_FormBodyInjectionRejected(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "form-inject-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/login",
				"body": "email={{email}}",
				"body_encoding": "form"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	hostileSubject := "a&role=admin"
	req, err := buildRequest(spec, context.Background(), hostileSubject)
	require.NoError(t, err, "buildRequest should succeed for form encoding")
	require.NotNil(t, req)

	bodyBytes, readErr := io.ReadAll(req.Body)
	require.NoError(t, readErr)

	// Parse the form values.
	vals, parseErr := url.ParseQuery(string(bodyBytes))
	require.NoError(t, parseErr, "on-wire form body must parse as URL-encoded form")

	// There must be exactly one parameter.
	assert.Len(t, vals, 1, "form body must have exactly one parameter (P0-3)")

	// The "role" key must NOT be present.
	_, hasRole := vals["role"]
	assert.False(t, hasRole, "injected role param must not appear in form body (P0-3)")

	// The "email" param must contain the literal subject.
	assert.Equal(t, hostileSubject, vals.Get("email"),
		"email param value must be the literal subject (P0-3)")
}

// TestBuildRequest_P0_4_PostSubURLRevalidation verifies P0-4 (R3+R4): when a
// URL template contains a placeholder in the host position and the subject
// yields a scheme-changing or structure-breaking value, buildRequest must
// return an error after re-parsing the final URL.
func TestBuildRequest_P0_4_PostSubURLRevalidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject string
	}{
		{
			name:    "domain yields file: scheme",
			subject: "user@file:",
		},
		{
			name:    "domain contains CRLF control char",
			subject: "user@evil\r\n.com",
		},
		{
			name:    "domain is empty resulting in bad URL",
			subject: "user",
		},
	}

	// Template with domain in host position.
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "post-sub-url-test",
			"request": {
				"method": "GET",
				"url": "https://{{domain}}/api/check"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := buildRequest(spec, context.Background(), tc.subject)
			// Either an error is returned (expected for bad URLs), or if the
			// subject happens to yield a valid URL, verify no scheme bypass.
			if err != nil {
				return // Good: rejected as expected.
			}
			require.NotNil(t, req, "non-error buildRequest must return a non-nil *http.Request")
			t.Logf("subject %q produced URL %q (scheme=%q)", tc.subject, req.URL.String(), req.URL.Scheme)
			assert.True(t, req.URL.Scheme == "http" || req.URL.Scheme == "https",
				"on success, URL scheme must be http or https (no scheme bypass)")
		})
	}

	// Specifically test that a subject that would change the scheme is rejected.
	t.Run("subject causes scheme change to non-http(s) → error", func(t *testing.T) {
		t.Parallel()
		specDynamic := buildSpecForRequest(t, []byte(`{
			"version": "1",
			"oracle": {
				"name": "scheme-change-test",
				"request": {
					"method": "GET",
					"url": "https://example.com/api/{{localpart}}"
				},
				"match": {
					"rules": [{"when": {"status": 200}, "verdict": "exists"}],
					"default": "error"
				}
			}
		}`))

		// Normal path traversal attempt — must be escaped, not executed.
		req, err := buildRequest(specDynamic, context.Background(), "../../admin@example.com")
		if err != nil {
			return // acceptable: rejected
		}
		require.NotNil(t, req)
		// If allowed, the path must not contain unescaped "../".
		assert.NotContains(t, req.URL.Path, "../",
			"path traversal must be escaped, not literal (P0-4)")
	})
}

// TestBuildRequest_URLPathEscaping verifies that a subject used in a URL path
// segment has path-unsafe characters escaped with url.PathEscape.
func TestBuildRequest_URLPathEscaping(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "path-escape-test",
			"request": {
				"method": "GET",
				"url": "https://example.com/users/{{localpart}}"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(spec, context.Background(), "../../admin@example.com")
	if err != nil {
		// If the implementation rejects the traversal attempt entirely, that is also acceptable.
		return
	}
	require.NotNil(t, req)
	// The path must not contain literal `../`.
	assert.NotContains(t, req.URL.EscapedPath(), "/../",
		"path traversal segments must be escaped (P0-4)")
	assert.NotContains(t, req.URL.Path, "../",
		"path traversal must not survive into the final request path")
}

// TestBuildRequest_URLQueryEscaping verifies that a subject used in a URL
// query value is escaped with url.QueryEscape, preventing injection.
func TestBuildRequest_URLQueryEscaping(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "query-escape-test",
			"request": {
				"method": "GET",
				"url": "https://example.com/api?email={{email}}"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(spec, context.Background(), "test@example.com&admin=1")
	require.NoError(t, err)
	require.NotNil(t, req)

	// The raw query must not contain an extra "admin" parameter.
	vals, parseErr := url.ParseQuery(req.URL.RawQuery)
	require.NoError(t, parseErr)
	_, hasAdmin := vals["admin"]
	assert.False(t, hasAdmin, "injected query param must not appear (R3)")
}

// TestBuildRequest_RawBodyControlCharRejected verifies that a raw-encoded body
// with a subject containing a control character (e.g. \n) is rejected.
func TestBuildRequest_RawBodyControlCharRejected(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "raw-ctrl-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/api",
				"body": "user={{username}}",
				"body_encoding": "raw"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(spec, context.Background(), "user\ninjected")
	require.Error(t, err, "raw body must reject subjects with control chars (R2)")
	assert.Nil(t, req)
}

// TestBuildRequest_NoStringsNewReplacer verifies that the request builder does
// not use a single global strings.NewReplacer over the assembled request
// (which would reintroduce R1+R2+R3 simultaneously).
// This is a static-analysis proxy: we confirm per-channel escaping works
// correctly for a case that would break under a naive replacer.
func TestBuildRequest_PerChannelEscaping_NotGlobalReplace(t *testing.T) {
	t.Parallel()
	// A subject that contains `&` (breaks form) but is safe in JSON.
	// With per-channel: form→QueryEscape, JSON→json-escape. Both correct.
	// With a naive single-replacer: either both wrong or one wrong.
	jsonSpec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "json-and-form-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/api",
				"body": "{\"user\":\"{{username}}\"}",
				"body_encoding": "json"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(jsonSpec, context.Background(), "alice&bob@example.com")
	require.NoError(t, err)
	require.NotNil(t, req)

	bodyBytes, _ := io.ReadAll(req.Body)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed),
		"JSON body must be valid; per-channel escaping must encode & as \\u0026 or literal in string")

	userVal, ok := parsed["user"]
	require.True(t, ok)
	assert.Equal(t, "alice&bob@example.com", userVal,
		"& must be JSON-escaped, not treated as form separator")
}

// TestBuildRequest_ValidRequest verifies that a clean, non-hostile subject
// produces a well-formed http.Request with the expected method, URL, and body.
func TestBuildRequest_ValidRequest(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "valid-req-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/forgot",
				"body": "{\"username\":\"{{username}}\"}",
				"body_encoding": "json",
				"headers": {
					"Content-Type": "application/json",
					"X-Tenant": "corp"
				}
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(spec, context.Background(), "jsmith@corp.com")
	require.NoError(t, err)
	require.NotNil(t, req)

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "https://example.com/forgot", req.URL.String())
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "corp", req.Header.Get("X-Tenant"))

	bodyBytes, _ := io.ReadAll(req.Body)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed))
	assert.Equal(t, "jsmith@corp.com", parsed["username"])
}

// TestBuildRequest_PlaceholdersSubstituted verifies that all four placeholder
// types are substituted into the request body correctly.
func TestBuildRequest_PlaceholdersSubstituted(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "ph-test",
			"request": {
				"method": "POST",
				"url": "https://example.com/api",
				"body": "{\"username\":\"{{username}}\",\"email\":\"{{email}}\",\"local\":\"{{localpart}}\",\"dom\":\"{{domain}}\"}",
				"body_encoding": "json"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	req, err := buildRequest(spec, context.Background(), "jsmith@acme.com")
	require.NoError(t, err)
	require.NotNil(t, req)

	bodyBytes, _ := io.ReadAll(req.Body)
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed))

	assert.Equal(t, "jsmith@acme.com", parsed["username"])
	assert.Equal(t, "jsmith@acme.com", parsed["email"])
	assert.Equal(t, "jsmith", parsed["local"])
	assert.Equal(t, "acme.com", parsed["dom"])
}

// TestBuildRequest_P0_5_SchemeAllowlistAtLoad verifies P0-5 (R4): the scheme
// allowlist is enforced at load time (Validate) for file:// and gopher://.
// This is a validate-level check (already tested in parse_test.go) but we
// confirm buildRequest never receives a spec with a bad load-time scheme.
func TestBuildRequest_P0_5_SchemeAllowlistAtLoad(t *testing.T) {
	t.Parallel()
	// Attempt to parse + validate a file:// spec.
	data := []byte(`{
		"version": "1",
		"oracle": {
			"name": "scheme-test",
			"request": {"method": "GET", "url": "file:///etc/passwd"},
			"match": {"rules": [{"when": {"status": 200}, "verdict": "exists"}], "default": "error"}
		}
	}`)
	spec, err := Parse(data)
	if err != nil {
		return // Parse-level rejection is fine.
	}
	require.Error(t, spec.Validate(),
		"Validate must reject file:// scheme (P0-5 / R4)")
}

// ---------------------------------------------------------------------------
// NF-1: userinfo authority injection — EXPECTED TO FAIL until production fix
// ---------------------------------------------------------------------------

// TestBuildRequest_RejectsUserinfoAuthority verifies that a subject whose value
// smuggles a userinfo "@" into the authority of the post-substitution URL is
// rejected by buildRequest. For example, with url "https://{{domain}}/x" and
// subject "a@evil.com@realhost.com", the {{domain}} placeholder resolves to
// "evil.com@realhost.com", making the parsed URL authority contain userinfo
// "evil.com" and host "realhost.com" — a credential-smuggling bypass.
//
// This test is INTENTIONALLY FAILING: the current code does not check u.User.
// A developer will add `if u.User != nil { return nil, fmt.Errorf(...) }` in
// buildRequestURL to make it pass.
func TestBuildRequest_RejectsUserinfoAuthority(t *testing.T) {
	t.Parallel()
	spec := buildSpecForRequest(t, []byte(`{
		"version": "1",
		"oracle": {
			"name": "userinfo-authority-test",
			"request": {
				"method": "GET",
				"url": "https://{{domain}}/x"
			},
			"match": {
				"rules": [{"when": {"status": 200}, "verdict": "exists"}],
				"default": "error"
			}
		}
	}`))

	// Subject "a@evil.com@realhost.com":
	//   - {{domain}} → "evil.com@realhost.com"  (derivePlaceholders splits on first @)
	//   - Post-sub URL → "https://evil.com@realhost.com/x"
	//   - url.Parse sees host="realhost.com", userinfo="evil.com"
	// buildRequest must return a non-nil error for this case.
	_, err := buildRequest(spec, context.Background(), "a@evil.com@realhost.com")
	require.Error(t, err, "buildRequest must reject userinfo in post-substitution URL authority (NF-1)")
}
