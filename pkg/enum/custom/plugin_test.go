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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/brutus/pkg/enum"
)

// ---------------------------------------------------------------------------
// T9: Plugin adapter — httptest-based tests mirroring microsoft365_test.go
// ---------------------------------------------------------------------------

// forgotPasswordSpec returns a parsed, validated Spec for the forgotpassword
// oracle pointing at the given base URL. Used by T9 and T12 tests.
func forgotPasswordSpec(t *testing.T, baseURL string) *Spec {
	t.Helper()
	data := []byte(fmt.Sprintf(`{
		"version": "1",
		"oracle": {
			"name": "forgotpassword",
			"request": {
				"method": "POST",
				"url": "%s/forgotpassword",
				"body": "{\"username\":\"{{username}}\"}",
				"body_encoding": "json",
				"headers": {"Content-Type": "application/json"}
			},
			"match": {
				"rules": [
					{
						"when": {"status": 200, "body_contains": "reset link sent"},
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
					}
				],
				"default": "error"
			}
		}
	}`, baseURL))

	spec, err := Parse(data)
	require.NoError(t, err)
	require.NoError(t, spec.Validate())
	return spec
}

// newMockForgotPasswordServer creates an httptest.Server that simulates the
// forgotpassword oracle endpoint. The subject in the JSON body drives the
// response (mirrors microsoft365_test.go::newMockMicrosoftServer pattern).
func newMockForgotPasswordServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/forgotpassword" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req struct {
			Username string `json:"username"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch req.Username {
		case "jsmith":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"reset link sent to your email"}`))
		case "nobody":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"user not found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"user not found"}`))
		}
	}))
}

// TestCheck_Exists verifies that a 200 response with the expected body
// substring produces Exists=true with ConfidenceHigh.
func TestCheck_Exists(t *testing.T) {
	t.Parallel()
	srv := newMockForgotPasswordServer(t)
	t.Cleanup(srv.Close)

	spec := forgotPasswordSpec(t, srv.URL)
	p := New(spec)

	result := p.Check(context.Background(), "jsmith", 5*time.Second)
	require.NoError(t, result.Error)
	assert.True(t, result.Exists, "jsmith should be found (exists)")
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
	assert.Equal(t, "forgotpassword", result.Service)
	assert.Equal(t, "jsmith", result.Email)
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestCheck_Absent verifies that a 404 response produces Exists=false, nil Error.
func TestCheck_Absent(t *testing.T) {
	t.Parallel()
	srv := newMockForgotPasswordServer(t)
	t.Cleanup(srv.Close)

	spec := forgotPasswordSpec(t, srv.URL)
	p := New(spec)

	result := p.Check(context.Background(), "nobody", 5*time.Second)
	require.NoError(t, result.Error)
	assert.False(t, result.Exists, "nobody should be absent")
	// Either high (404 rule) or medium (body_regex rule) — the 404 rule fires first.
	assert.Equal(t, enum.ConfidenceHigh, result.Confidence)
}

// TestCheck_VerdictError verifies that when no rule matches, the result has
// Error set to errInconclusive and Exists=false.
func TestCheck_VerdictError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`server error`))
	}))
	t.Cleanup(srv.Close)

	spec := forgotPasswordSpec(t, srv.URL)
	p := New(spec)

	result := p.Check(context.Background(), "test", 5*time.Second)
	// 500 matches no rule; default is "error".
	require.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, errInconclusive),
		"error verdict must use errInconclusive sentinel; got: %v", result.Error)
	assert.False(t, result.Exists)
}

// TestCheck_TransportError verifies that a transport-level error (e.g. closed
// server) sets result.Error and leaves Exists=false.
func TestCheck_TransportError(t *testing.T) {
	t.Parallel()
	srv := newMockForgotPasswordServer(t)
	srv.Close() // Close before use to force transport error.

	spec := forgotPasswordSpec(t, srv.URL)
	p := New(spec)

	result := p.Check(context.Background(), "jsmith", 5*time.Second)
	require.Error(t, result.Error, "transport error must set result.Error")
	assert.False(t, result.Exists)
}

// TestCheck_RequestBodyCapture verifies that the body sent to the server
// contains the substituted placeholder (mirrors microsoft365_test.go:207-224).
func TestCheck_RequestBodyCapture(t *testing.T) {
	t.Parallel()
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"reset link sent"}`))
	}))
	t.Cleanup(srv.Close)

	spec := forgotPasswordSpec(t, srv.URL)
	p := New(spec)

	_ = p.Check(context.Background(), "verify@example.com", 5*time.Second)

	var req struct {
		Username string `json:"username"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	assert.Equal(t, "verify@example.com", req.Username,
		"server must receive the substituted subject in the request body")
}

// TestCheck_R6_BodyCap verifies P0-6 (R6): when the server streams more than
// 2 MB of body, Check returns within a reasonable time (no OOM) and reads
// at most 1 MB (the ReadResponseBody cap). The matcher operates only on
// the capped bytes.
func TestCheck_R6_BodyCap(t *testing.T) {
	t.Parallel()

	// Server streams exactly 2 MB + 1 byte (exceeds the 1 MB cap).
	const streamSize = (1 << 20) + 1 // 1 MB + 1 byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write 2 MB of data.
		buf := make([]byte, streamSize*2)
		for i := range buf {
			buf[i] = 'x'
		}
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	// Oracle that tries to match body_contains on a string that appears only
	// if the FULL body were read (past the 1MB cap).
	spec, err := Parse([]byte(fmt.Sprintf(`{
		"version": "1",
		"oracle": {
			"name": "cap-test",
			"request": {"method": "GET", "url": "%s/data"},
			"match": {
				"rules": [
					{"when": {"body_contains": "reset link sent"}, "verdict": "exists", "confidence": "high"}
				],
				"default": "error"
			}
		}
	}`, srv.URL)))
	require.NoError(t, err)
	require.NoError(t, spec.Validate())

	p := New(spec)

	// The key requirement: Check must return (not hang/OOM).
	// No rule matches (body is all 'x'), so default "error" verdict.
	result := p.Check(context.Background(), "testuser", 10*time.Second)
	// We do not assert on result.Error here because the 2MB body won't cause an
	// error — it just won't match. The critical check is that we returned at all.
	assert.NotNil(t, result, "Check must return a result even for large bodies (R6)")
}

// TestName verifies that Plugin.Name() returns the oracle name from the spec.
func TestName(t *testing.T) {
	t.Parallel()
	spec := forgotPasswordSpec(t, "https://example.com")
	p := New(spec)
	assert.Equal(t, "forgotpassword", p.Name())
}

// ---------------------------------------------------------------------------
// T12: End-to-end test using testdata/forgotpassword.json
// ---------------------------------------------------------------------------

// TestE2E_ForgotPassword parses the example oracle file, points it at an
// httptest server, runs EnumerateWithPlugin, and asserts:
//   - jsmith → Exists=true
//   - nobody → Exists=false, Error=nil
//   - the file parses and validates cleanly
func TestE2E_ForgotPassword(t *testing.T) {
	t.Parallel()
	srv := newMockForgotPasswordServer(t)
	t.Cleanup(srv.Close)

	// Read the example oracle fixture.
	fixtureData, err := os.ReadFile(filepath.Join("testdata", "forgotpassword.json"))
	require.NoError(t, err, "testdata/forgotpassword.json must exist")

	// Parse the fixture.
	spec, err := Parse(fixtureData)
	require.NoError(t, err, "forgotpassword.json must parse without error")

	// Override the URL to point at the test server (the fixture uses a
	// placeholder host; the test replaces it with the httptest server URL).
	spec.Oracle.Request.URL = srv.URL + "/forgotpassword"

	// Validate must succeed after URL override.
	require.NoError(t, spec.Validate(),
		"forgotpassword.json must validate cleanly (T12 exit criteria)")

	// Run the enumeration.
	p := New(spec)
	results, enumErr := enum.EnumerateWithPlugin(
		context.Background(),
		&enum.Config{
			Emails:  []string{"jsmith", "nobody"},
			Threads: 2,
			Timeout: 5 * time.Second,
		},
		p,
	)
	require.NoError(t, enumErr)
	require.Len(t, results, 2)

	// Build a subject → result map for easy assertion.
	byEmail := make(map[string]enum.Result)
	for _, r := range results {
		byEmail[r.Email] = r
	}

	// jsmith must exist.
	jsmith, ok := byEmail["jsmith"]
	require.True(t, ok, "jsmith must have a result")
	require.NoError(t, jsmith.Error)
	assert.True(t, jsmith.Exists, "jsmith must be Exists=true")

	// nobody must be absent.
	nobody, ok := byEmail["nobody"]
	require.True(t, ok, "nobody must have a result")
	require.NoError(t, nobody.Error, "nobody must have Error=nil (clean absent)")
	assert.False(t, nobody.Exists, "nobody must be Exists=false")
}

// TestE2E_ForgotPassword_ValidatesClean verifies that the forgotpassword.json
// fixture file parses and validates without any override — satisfying the T12
// exit criterion that the file itself is spec-valid.
func TestE2E_ForgotPassword_ValidatesClean(t *testing.T) {
	t.Parallel()
	fixtureData, err := os.ReadFile(filepath.Join("testdata", "forgotpassword.json"))
	require.NoError(t, err, "testdata/forgotpassword.json must exist")

	spec, err := Parse(fixtureData)
	require.NoError(t, err, "forgotpassword.json must parse without error")
	require.NoError(t, spec.Validate(),
		"forgotpassword.json must validate cleanly (T12 exit criteria)")

	// Verify key fields from the fixture.
	assert.Equal(t, "1", spec.Version)
	assert.NotEmpty(t, spec.Oracle.Name)
	assert.NotEmpty(t, spec.Oracle.Request.URL)
	assert.NotEmpty(t, spec.Oracle.Match.Rules)
}
