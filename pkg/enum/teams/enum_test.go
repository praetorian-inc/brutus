// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teams

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestEnumerator creates an Enumerator with overridden base URLs pointing at
// the provided test servers. It mirrors auth_test.go's newTestClient helper.
func newTestEnumerator(t *testing.T, searchSrv, presenceSrv *httptest.Server, presence bool) *Enumerator {
	t.Helper()
	const accessToken = "test-access-token-sentinel"
	const refreshToken = "test-refresh-token-sentinel"
	e, err := NewEnumerator(accessToken, refreshToken, "", 5*time.Second, presence)
	require.NoError(t, err)
	if searchSrv != nil {
		// searchBaseURL is a fmt format string with %s for the escaped email.
		e.searchBaseURL = searchSrv.URL + "/%s"
	}
	if presenceSrv != nil {
		e.presenceBaseURL = presenceSrv.URL + "/presence"
	}
	return e
}

// searchServerReturning builds an httptest.Server that always responds with the
// given status code and JSON body.
func searchServerReturning(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

// ---------------------------------------------------------------------------
// Test 1: Existence YES
// ---------------------------------------------------------------------------

func TestEnumerateOne_ExistenceYes(t *testing.T) {
	srv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Alice","mri":"8:orgid:abc"}]`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	res := e.EnumerateOne(context.Background(), "alice@contoso.com")

	assert.Equal(t, ExistenceYes, res.Exists)
	assert.Equal(t, "Alice", res.DisplayName)
	assert.Equal(t, "8:orgid:abc", res.MRI)
	assert.Equal(t, "alice@contoso.com", res.Email)
	assert.NoError(t, res.Error)
}

// ---------------------------------------------------------------------------
// Test 2: Existence NO — empty array and non-array body
// ---------------------------------------------------------------------------

func TestEnumerateOne_ExistenceNo_EmptyArray(t *testing.T) {
	srv := searchServerReturning(http.StatusOK, `[]`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	res := e.EnumerateOne(context.Background(), "nobody@contoso.com")

	assert.Equal(t, ExistenceNo, res.Exists)
	assert.NoError(t, res.Error)
}

func TestEnumerateOne_ExistenceNo_NonArrayBody(t *testing.T) {
	// A JSON object (non-array) body — must NOT be ExistenceYes and must NOT panic.
	srv := searchServerReturning(http.StatusOK, `{"message":"not found"}`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	res := e.EnumerateOne(context.Background(), "object@contoso.com")

	assert.NotEqual(t, ExistenceYes, res.Exists,
		"a non-array 200 body must not produce ExistenceYes")
}

// ---------------------------------------------------------------------------
// Test 3: Blocked (403) — error must not contain the access token
// ---------------------------------------------------------------------------

func TestEnumerateOne_Blocked(t *testing.T) {
	srv := searchServerReturning(http.StatusForbidden, `{"error":"forbidden"}`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	// Access token set by newTestEnumerator
	const token = "test-access-token-sentinel"
	res := e.EnumerateOne(context.Background(), "blocked@contoso.com")

	assert.Equal(t, ExistenceBlocked, res.Exists)
	// If there is an error message, it must not contain the access token.
	if res.Error != nil {
		assert.NotContains(t, res.Error.Error(), token,
			"Error must not contain the access token")
	}
}

// ---------------------------------------------------------------------------
// Test 4: 401 + refresh success — refresh invoked exactly once
// ---------------------------------------------------------------------------

func TestEnumerateOne_UnauthorizedThenRefresh(t *testing.T) {
	var callCount atomic.Int32
	var refreshCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// First call: 401.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Second call (after refresh): user found.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"displayName":"Bob","mri":"8:orgid:bob"}]`))
	}))
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	e.SetRefreshFunc(func(ctx context.Context) (string, error) {
		refreshCount.Add(1)
		return "new-access-token", nil
	})

	res := e.EnumerateOne(context.Background(), "bob@contoso.com")

	assert.Equal(t, ExistenceYes, res.Exists)
	assert.Equal(t, "Bob", res.DisplayName)
	assert.Equal(t, int32(1), refreshCount.Load(), "refresh func must be invoked exactly once")
}

// ---------------------------------------------------------------------------
// Test 5: 401 + no refresh -> ExistenceUnknown, error mentions "unauthorized",
//
//	error does NOT contain the token
//
// ---------------------------------------------------------------------------

func TestEnumerateOne_UnauthorizedNoRefresh(t *testing.T) {
	srv := searchServerReturning(http.StatusUnauthorized, "")
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	const token = "test-access-token-sentinel"

	res := e.EnumerateOne(context.Background(), "unauth@contoso.com")

	assert.Equal(t, ExistenceUnknown, res.Exists)
	require.Error(t, res.Error, "should have an error for 401 with no refresh func")
	assert.Contains(t, strings.ToLower(res.Error.Error()), "unauthorized",
		"error should mention unauthorized")
	assert.NotContains(t, res.Error.Error(), token,
		"error must not contain the access token")
}

// ---------------------------------------------------------------------------
// Test 6: 401 loop guard — server always returns 401, refresh always succeeds,
//
//	result must be ExistenceUnknown and test must complete quickly
//
// ---------------------------------------------------------------------------

func TestEnumerateOne_UnauthorizedLoopGuard(t *testing.T) {
	var refreshCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	e.SetRefreshFunc(func(ctx context.Context) (string, error) {
		refreshCount.Add(1)
		return "ever-refreshed-token", nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := e.EnumerateOne(ctx, "loop@contoso.com")

	assert.Equal(t, ExistenceUnknown, res.Exists,
		"persistent 401s must yield ExistenceUnknown, not loop forever")
	assert.LessOrEqual(t, refreshCount.Load(), int32(1),
		"refresh must be invoked at most once regardless of repeated 401s")
}

// ---------------------------------------------------------------------------
// Test 7: Other status (500) -> ExistenceUnknown, error mentions 500
// ---------------------------------------------------------------------------

func TestEnumerateOne_ServerError500(t *testing.T) {
	srv := searchServerReturning(http.StatusInternalServerError, `{"error":"internal"}`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	res := e.EnumerateOne(context.Background(), "error@contoso.com")

	assert.Equal(t, ExistenceUnknown, res.Exists)
	require.Error(t, res.Error)
	assert.Contains(t, res.Error.Error(), "500",
		"error should mention the unexpected status code")
}

// ---------------------------------------------------------------------------
// Test 8: Malformed JSON on 200 -> ExistenceUnknown — actually per production
//
//	code: json.Unmarshal errors return nil (silent decode failure means ExistenceNo).
//	The comment in search() says "A non-array (or otherwise non-matching) body
//	decodes to a zero-length slice, which the caller treats as 'not found'."
//	So malformed JSON produces ExistenceNo (not ExistenceUnknown) and no Error.
//	This test pins that actual behavior and verifies no token leaks.
//
// ---------------------------------------------------------------------------

func TestEnumerateOne_MalformedJSON(t *testing.T) {
	srv := searchServerReturning(http.StatusOK, `not-valid-json{{`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	const token = "test-access-token-sentinel"

	res := e.EnumerateOne(context.Background(), "malformed@contoso.com")

	// Per production code: malformed JSON returns zero-slice which → ExistenceNo.
	// Verified: search() calls json.Unmarshal and on error returns nil (no error),
	// 200 status. EnumerateOne sees len(users)==0 → ExistenceNo.
	assert.Equal(t, ExistenceNo, res.Exists,
		"malformed JSON on 200 should produce ExistenceNo (production decode path)")
	if res.Error != nil {
		assert.NotContains(t, res.Error.Error(), token,
			"error must not contain the access token")
	}
}

// ---------------------------------------------------------------------------
// Test 9: Presence success
// ---------------------------------------------------------------------------

func TestEnumerateOne_PresenceSuccess(t *testing.T) {
	searchSrv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Carol","mri":"8:orgid:carol"}]`)
	defer searchSrv.Close()

	presenceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"presence":{"availability":"Available","deviceType":"Desktop"}}]`))
	}))
	defer presenceSrv.Close()

	e := newTestEnumerator(t, searchSrv, presenceSrv, true /* presence enabled */)
	res := e.EnumerateOne(context.Background(), "carol@contoso.com")

	assert.Equal(t, ExistenceYes, res.Exists)
	assert.Equal(t, "Carol", res.DisplayName)
	assert.Equal(t, "8:orgid:carol", res.MRI)
	assert.Equal(t, "Available", res.Availability)
	assert.Equal(t, "Desktop", res.DeviceType)
	assert.NoError(t, res.Error)
}

// ---------------------------------------------------------------------------
// Test 10: Presence failure is non-fatal
// ---------------------------------------------------------------------------

func TestEnumerateOne_PresenceFailureNonFatal(t *testing.T) {
	searchSrv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Dave","mri":"8:orgid:dave"}]`)
	defer searchSrv.Close()

	// Presence server returns 500.
	presenceSrv := searchServerReturning(http.StatusInternalServerError, `{"error":"down"}`)
	defer presenceSrv.Close()

	e := newTestEnumerator(t, searchSrv, presenceSrv, true)
	res := e.EnumerateOne(context.Background(), "dave@contoso.com")

	// Existence result preserved.
	assert.Equal(t, ExistenceYes, res.Exists)
	assert.Equal(t, "Dave", res.DisplayName)
	// Presence fields empty (failure is non-fatal).
	assert.Empty(t, res.Availability)
	assert.Empty(t, res.DeviceType)
	// No error from presence failure.
	assert.NoError(t, res.Error)
}

func TestEnumerateOne_PresenceEmptyArrayNonFatal(t *testing.T) {
	searchSrv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Eve","mri":"8:orgid:eve"}]`)
	defer searchSrv.Close()

	// Presence server returns empty array.
	presenceSrv := searchServerReturning(http.StatusOK, `[]`)
	defer presenceSrv.Close()

	e := newTestEnumerator(t, searchSrv, presenceSrv, true)
	res := e.EnumerateOne(context.Background(), "eve@contoso.com")

	assert.Equal(t, ExistenceYes, res.Exists)
	assert.Empty(t, res.Availability)
	assert.Empty(t, res.DeviceType)
	assert.NoError(t, res.Error)
}

// ---------------------------------------------------------------------------
// Test 11: Request assertions — headers, authorization, URL encoding
// ---------------------------------------------------------------------------

func TestEnumerateOne_RequestHeaders(t *testing.T) {
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"displayName":"Frank","mri":"8:orgid:frank"}]`))
	}))
	defer srv.Close()

	e, err := NewEnumerator("my-access-token", "", "", 5*time.Second, false)
	require.NoError(t, err)
	e.searchBaseURL = srv.URL + "/%s"

	_ = e.EnumerateOne(context.Background(), "frank@contoso.com")

	require.NotNil(t, captured, "server must have received a request")
	assert.Equal(t, clientVersion, captured.Header.Get("X-Ms-Client-Version"),
		"X-Ms-Client-Version must equal clientVersion constant")
	assert.NotEmpty(t, captured.Header.Get("User-Agent"),
		"User-Agent must be non-empty")
	assert.Equal(t, "Bearer my-access-token", captured.Header.Get("Authorization"),
		"Authorization must be Bearer <token>")
	// The email must appear in the request URL (percent-encoded or raw).
	assert.Contains(t, captured.URL.String(), "frank",
		"email must be reflected in the search URL path")
}

func TestEnumerateOne_EmailURLEncoding(t *testing.T) {
	// url.PathEscape leaves '+' as a literal '+' because '+' is a valid
	// sub-delimiter in a URI path segment (RFC 3986 §3.3).  The production
	// code uses url.PathEscape (enum.go search()), which is correct: TeamsEnum
	// sends the raw email and the Teams API accepts '+' unencoded in the path.
	t.Run("plus preserved as literal", func(t *testing.T) {
		var capturedPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		e := newTestEnumerator(t, srv, nil, false)
		_ = e.EnumerateOne(context.Background(), "user+tag@example.com")

		// url.PathEscape does NOT escape '+'; it stays as a literal '+' in the path.
		assert.Contains(t, capturedPath, "+tag@",
			"url.PathEscape preserves '+' in path segments; literal '+' must appear in path")
		assert.NotContains(t, capturedPath, "%2B",
			"url.PathEscape does not encode '+', so '%2B' must NOT appear")
	})

	// url.PathEscape DOES escape '/' (to '%2F'), so a malicious email containing a
	// slash cannot escape the intended path segment (path-injection safety).
	t.Run("slash percent-encoded for path-injection safety", func(t *testing.T) {
		var capturedRawPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// r.URL.RawPath preserves percent-encoding as sent on the wire.
			// r.URL.Path would decode %2F back to '/', masking the escaping.
			capturedRawPath = r.URL.RawPath
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		e := newTestEnumerator(t, srv, nil, false)
		_ = e.EnumerateOne(context.Background(), "evil/../x@example.com")

		// url.PathEscape encodes '/' → '%2F', preventing the injected '../' from
		// traversing out of the intended path segment.  The wire encoding is
		// visible in r.URL.RawPath (not r.URL.Path, which decodes %2F back to '/').
		assert.Contains(t, capturedRawPath, "%2F",
			"url.PathEscape must encode '/' to '%2F' to prevent path-segment injection")
	})
}

func TestEnumerateOne_PresenceRequestAssertions(t *testing.T) {
	searchSrv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Gail","mri":"8:orgid:gail"}]`)
	defer searchSrv.Close()

	var capturedPresenceReq *http.Request
	var capturedPresenceBody []byte
	presenceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPresenceReq = r
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		capturedPresenceBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"presence":{"availability":"Busy","deviceType":"Mobile"}}]`))
	}))
	defer presenceSrv.Close()

	e := newTestEnumerator(t, searchSrv, presenceSrv, true)
	_ = e.EnumerateOne(context.Background(), "gail@contoso.com")

	require.NotNil(t, capturedPresenceReq, "presence server must have been called")
	assert.Equal(t, http.MethodPost, capturedPresenceReq.Method,
		"presence request must use POST")
	assert.Equal(t, "application/json", capturedPresenceReq.Header.Get("Content-Type"),
		"presence Content-Type must be application/json")

	// Body must be [{"mri":"8:orgid:gail"}].
	var body []presenceRequest
	require.NoError(t, json.Unmarshal(capturedPresenceBody, &body),
		"presence request body must be valid JSON")
	require.Len(t, body, 1)
	assert.Equal(t, "8:orgid:gail", body[0].MRI,
		"presence request body MRI must match the search result MRI")
}

// ---------------------------------------------------------------------------
// Test 12: Concurrency — Enumerate over 6 emails with threads=2
// ---------------------------------------------------------------------------

func TestEnumerate_Concurrency(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)

		// Track maximum observed concurrency.
		for {
			prev := maxInFlight.Load()
			if cur <= prev {
				break
			}
			if maxInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	e, err := NewEnumerator("tok-A", "", "", 5*time.Second, false)
	require.NoError(t, err)
	e.searchBaseURL = srv.URL + "/%s"

	emails := []string{
		"a@x.com", "b@x.com", "c@x.com", "d@x.com", "e@x.com", "f@x.com",
	}
	results := e.Enumerate(context.Background(), emails, 2, 0, 0)

	// All 6 results returned.
	require.Len(t, results, 6, "must return one result per email")
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email,
			"results must preserve input order")
	}

	// Concurrency must not exceed 2 (threads parameter).
	assert.LessOrEqual(t, maxInFlight.Load(), int32(2),
		"in-flight requests must never exceed threads=2")
}

// ---------------------------------------------------------------------------
// Test 13: Concurrent 401→refresh→retry — regression for the data race on
// e.accessToken.
//
// Background: worker goroutines in Enumerate call e.token() (which reads
// e.accessToken) while a 401-triggered refreshOnce() writes e.accessToken.
// The fix guards both paths under e.mu. Running under -race, this test would
// detect a DATA RACE if the lock were ever removed from token() or
// refreshOnce(), even if all results happen to be correct.
//
// Design: the httptest server uses an atomic counter so only the very first
// request receives HTTP 401; all subsequent requests succeed. This guarantees
// exactly one refreshOnce() call while many goroutines are concurrently
// reading e.token() — maximizing the read/write overlap the race detector
// needs to observe.
// ---------------------------------------------------------------------------

func TestEnumerate_ConcurrentRefreshNoRace(t *testing.T) {
	var reqCount atomic.Int32
	var refreshCount atomic.Int32

	// Server: first call → 401, all subsequent → 200 with a valid user.
	// Using an atomic counter makes the behavior deterministic across
	// goroutines without any mutex in the handler.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"displayName":"U","mri":"8:orgid:u"}]`))
	}))
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	e.SetRefreshFunc(func(ctx context.Context) (string, error) {
		refreshCount.Add(1)
		return "refreshed-access-token", nil
	})

	// 50 emails × 8 concurrent workers creates enough goroutines that the
	// first worker's 401 fires while many others are concurrently in
	// e.token(), giving the race detector its best chance to observe the
	// unsynchronised read/write.
	const numEmails = 50
	const numThreads = 8
	emails := make([]string, numEmails)
	for i := range emails {
		emails[i] = fmt.Sprintf("user%d@contoso.com", i)
	}

	results := e.Enumerate(context.Background(), emails, numThreads, 0, 0)

	// Every email must produce exactly one result.
	require.Len(t, results, numEmails, "must return one result per email")

	// All results must correspond to the correct email (order preserved).
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email, "result[%d] email must match input order", i)
	}

	// The refresh func must be invoked exactly once (refreshOnce semantics).
	assert.Equal(t, int32(1), refreshCount.Load(),
		"refresh func must be invoked exactly once across all concurrent goroutines")

	// Post-refresh requests succeed (status 200 with a user); the one request
	// that got 401 and triggered the refresh also retries with the new token
	// and succeeds. Every result must be ExistenceYes (no transport errors).
	for _, r := range results {
		assert.Equal(t, ExistenceYes, r.Exists,
			"all results must be ExistenceYes after successful refresh")
		assert.NoError(t, r.Error)
	}
}

// ---------------------------------------------------------------------------
// Test 13: P0-1 token-safety table — error paths must not leak tokens
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test: ParsesConfigFields — externalsearchv3 rich body: type, tenantId,
// userPrincipalName, objectId, accountEnabled, featureSettings.coExistenceMode
// ---------------------------------------------------------------------------

func TestEnumerateOne_ParsesConfigFields(t *testing.T) {
	srv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Paul Davis","mri":"8:orgid:abc","type":"Federated","tenantId":"t-123","userPrincipalName":"paul.davis@kindermorgan.com","objectId":"o-456","accountEnabled":true,"featureSettings":{"coExistenceMode":"TeamsOnly"}}]`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	res := e.EnumerateOne(context.Background(), "paul.davis@kindermorgan.com")

	require.Equal(t, ExistenceYes, res.Exists)
	assert.Equal(t, "Federated", res.Type)
	assert.Equal(t, "t-123", res.TenantID)
	assert.Equal(t, "paul.davis@kindermorgan.com", res.UserPrincipalName)
	assert.Equal(t, "o-456", res.ObjectID)
	require.NotNil(t, res.AccountEnabled, "AccountEnabled must be parsed (not nil)")
	assert.True(t, *res.AccountEnabled, "AccountEnabled must be true")
	assert.Equal(t, "TeamsOnly", res.CoExistenceMode)
	assert.NoError(t, res.Error)
}

// ---------------------------------------------------------------------------
// Test: Presence parses sourceNetwork and both OOO note locations
// ---------------------------------------------------------------------------

func TestEnumerateOne_PresenceParsesSourceNetworkAndOOO(t *testing.T) {
	// Sub-test 1: OOO note under presence.outOfOfficeNote (direct path).
	t.Run("direct outOfOfficeNote", func(t *testing.T) {
		searchSrv := searchServerReturning(http.StatusOK,
			`[{"displayName":"Paul Davis","mri":"8:orgid:abc"}]`)
		defer searchSrv.Close()

		presenceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"mri":"8:orgid:abc","presence":{"sourceNetwork":"Federated","availability":"Busy","deviceType":"Mobile","outOfOfficeNote":{"message":"Back Monday - call Jane 555-1234"}}}]`))
		}))
		defer presenceSrv.Close()

		e := newTestEnumerator(t, searchSrv, presenceSrv, true)
		res := e.EnumerateOne(context.Background(), "paul.davis@kindermorgan.com")

		assert.Equal(t, ExistenceYes, res.Exists)
		assert.Equal(t, "Federated", res.SourceNetwork)
		assert.Equal(t, "Busy", res.Availability)
		assert.Equal(t, "Mobile", res.DeviceType)
		assert.Contains(t, res.OutOfOfficeNote, "Back Monday",
			"OOO note from presence.outOfOfficeNote.message must be parsed")
		assert.NoError(t, res.Error)
	})

	// Sub-test 2: OOO note under presence.calendarData.outOfOfficeNote (fallback path).
	t.Run("calendarData outOfOfficeNote fallback", func(t *testing.T) {
		searchSrv := searchServerReturning(http.StatusOK,
			`[{"displayName":"Jane","mri":"8:orgid:xyz"}]`)
		defer searchSrv.Close()

		presenceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"mri":"8:orgid:xyz","presence":{"sourceNetwork":"Unknown","calendarData":{"outOfOfficeNote":{"message":"OOO via calendar"}}}}]`))
		}))
		defer presenceSrv.Close()

		e := newTestEnumerator(t, searchSrv, presenceSrv, true)
		res := e.EnumerateOne(context.Background(), "jane@contoso.com")

		assert.Equal(t, ExistenceYes, res.Exists)
		assert.Equal(t, "Unknown", res.SourceNetwork)
		assert.Equal(t, "OOO via calendar", res.OutOfOfficeNote,
			"OOO note from calendarData fallback path must be parsed")
		assert.NoError(t, res.Error)
	})
}

// ---------------------------------------------------------------------------
// Test: DerivePosture — table-driven coverage of all aggregation logic
// ---------------------------------------------------------------------------

func TestDerivePosture(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name    string
		results []EnumResult
		check   func(t *testing.T, p TenantPosture)
	}{
		{
			name: "all yes with one Federated type",
			results: []EnumResult{
				{Exists: ExistenceYes, Type: "Federated"},
				{Exists: ExistenceYes, Type: "Member"},
				{Exists: ExistenceYes},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.Equal(t, "open", p.ExternalChatAllowed)
				assert.True(t, p.FederatedObserved, "FederatedObserved must be true when Type==\"Federated\"")
				assert.Equal(t, 3, p.UsersFound)
			},
		},
		{
			name: "all blocked 403",
			results: []EnumResult{
				{Exists: ExistenceBlocked},
				{Exists: ExistenceBlocked},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.Equal(t, "blocked", p.ExternalChatAllowed)
				assert.Equal(t, 2, p.Blocked403)
				assert.Equal(t, 0, p.UsersFound)
			},
		},
		{
			name: "all no or unknown",
			results: []EnumResult{
				{Exists: ExistenceNo},
				{Exists: ExistenceUnknown},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.Equal(t, "unknown", p.ExternalChatAllowed)
				assert.Equal(t, 0, p.UsersFound)
				assert.Equal(t, 0, p.Blocked403)
			},
		},
		{
			name: "presence fields visible and OOO count",
			results: []EnumResult{
				{Exists: ExistenceYes, Availability: "Busy", OutOfOfficeNote: "Back Monday"},
				{Exists: ExistenceYes, Availability: "Available", OutOfOfficeNote: ""},
				{Exists: ExistenceYes, OutOfOfficeNote: "Out until Friday"},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.True(t, p.PresenceVisible, "PresenceVisible must be true when any Availability is non-empty")
				assert.Equal(t, 2, p.OOOExposed, "OOOExposed must count results with non-empty OutOfOfficeNote")
			},
		},
		{
			name: "CoExistenceMode set to first non-empty",
			results: []EnumResult{
				{Exists: ExistenceYes, CoExistenceMode: ""},
				{Exists: ExistenceYes, CoExistenceMode: "TeamsOnly"},
				{Exists: ExistenceYes, CoExistenceMode: "SfBOnly"},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.Equal(t, "TeamsOnly", p.CoExistenceMode,
					"CoExistenceMode must be the first non-empty observed value")
			},
		},
		{
			name: "FederatedObserved via SourceNetwork Federated (case-insensitive Type)",
			results: []EnumResult{
				{Exists: ExistenceYes, Type: "federated"}, // lowercase — case-insensitive check
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.True(t, p.FederatedObserved,
					"FederatedObserved must be true for lowercase \"federated\" Type (case-insensitive)")
			},
		},
		{
			name: "FederatedObserved via SourceNetwork even when Type is empty",
			results: []EnumResult{
				{Exists: ExistenceYes, Type: "", SourceNetwork: "Federated"},
			},
			check: func(t *testing.T, p TenantPosture) {
				assert.True(t, p.FederatedObserved,
					"FederatedObserved must be true when SourceNetwork==\"Federated\" even with empty Type")
			},
		},
		{
			name: "AccountEnabled pointer does not affect aggregation",
			results: []EnumResult{
				{Exists: ExistenceYes, AccountEnabled: boolPtr(true)},
				{Exists: ExistenceYes, AccountEnabled: boolPtr(false)},
				{Exists: ExistenceYes, AccountEnabled: nil},
			},
			check: func(t *testing.T, p TenantPosture) {
				// All three are ExistenceYes; posture should aggregate them normally.
				assert.Equal(t, 3, p.UsersFound)
				assert.Equal(t, "open", p.ExternalChatAllowed)
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := DerivePosture("contoso.com", tc.results)
			tc.check(t, p)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: DerivePosture_DomainAndCounts — Total, UsersFound, Blocked403, Domain
// ---------------------------------------------------------------------------

func TestDerivePosture_DomainAndCounts(t *testing.T) {
	results := []EnumResult{
		{Exists: ExistenceYes},
		{Exists: ExistenceYes},
		{Exists: ExistenceBlocked},
		{Exists: ExistenceNo},
		{Exists: ExistenceUnknown},
	}

	p := DerivePosture("example.com", results)

	assert.Equal(t, "example.com", p.Domain, "Domain must pass through unchanged")
	assert.Equal(t, 5, p.Total, "Total must equal len(results)")
	assert.Equal(t, 2, p.UsersFound, "UsersFound must count ExistenceYes results only")
	assert.Equal(t, 1, p.Blocked403, "Blocked403 must count ExistenceBlocked results only")
	assert.Equal(t, "open", p.ExternalChatAllowed, "open because UsersFound > 0")
}

// ---------------------------------------------------------------------------
// Test: TokenSafetyTable
// ---------------------------------------------------------------------------

func TestEnumerateOne_TokenSafetyTable(t *testing.T) {
	const accessToken = "SUPER-SECRET-ACCESS-TOKEN"
	const refreshToken = "SUPER-SECRET-REFRESH-TOKEN"

	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "401 no refresh",
			statusCode: http.StatusUnauthorized,
			body:       "",
		},
		{
			name:       "500 server error",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"internal"}`,
		},
		{
			name:       "200 malformed JSON",
			statusCode: http.StatusOK,
			body:       `not-valid-json`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := searchServerReturning(tc.statusCode, tc.body)
			defer srv.Close()

			e, err := NewEnumerator(accessToken, refreshToken, "", 5*time.Second, false)
			require.NoError(t, err)
			e.searchBaseURL = srv.URL + "/%s"
			// No refresh function to keep test deterministic.

			res := e.EnumerateOne(context.Background(), "user@contoso.com")

			if res.Error != nil {
				assert.NotContains(t, res.Error.Error(), accessToken,
					"Error must not contain the access token")
				assert.NotContains(t, res.Error.Error(), refreshToken,
					"Error must not contain the refresh token")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Consumer-account filtering tests
// ---------------------------------------------------------------------------

// TestEnumerateOne_ConsumerOnly_IgnoredByDefault verifies that a search result
// containing a single consumer (8:live:) user is treated as ExistenceNo when
// includeConsumer is false (the default).
func TestEnumerateOne_ConsumerOnly_IgnoredByDefault(t *testing.T) {
	srv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Adam Harris","mri":"8:live:.cid.f9b1126819712f24"}]`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	// includeConsumer defaults to false — do NOT call SetIncludeConsumer.

	res := e.EnumerateOne(context.Background(), "adamharris@example.com")

	assert.Equal(t, ExistenceNo, res.Exists,
		"consumer-only result with includeConsumer=false must be ExistenceNo")
	assert.Empty(t, res.DisplayName,
		"DisplayName must be empty when consumer user is ignored")
	assert.Empty(t, res.MRI,
		"MRI must be empty when consumer user is ignored")
	assert.NoError(t, res.Error)
}

// TestEnumerateOne_ConsumerOnly_IncludedWhenFlagSet verifies that the same
// consumer-only search result becomes ExistenceYes when includeConsumer is true,
// and that all metadata comes from the consumer user entry.
func TestEnumerateOne_ConsumerOnly_IncludedWhenFlagSet(t *testing.T) {
	srv := searchServerReturning(http.StatusOK,
		`[{"displayName":"Adam Harris","mri":"8:live:.cid.f9b1126819712f24"}]`)
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	e.SetIncludeConsumer(true)

	res := e.EnumerateOne(context.Background(), "adamharris@example.com")

	assert.Equal(t, ExistenceYes, res.Exists,
		"consumer-only result with includeConsumer=true must be ExistenceYes")
	assert.Equal(t, "Adam Harris", res.DisplayName,
		"DisplayName must come from the consumer user entry")
	assert.Equal(t, "8:live:.cid.f9b1126819712f24", res.MRI,
		"MRI must be the 8:live: MRI from the consumer user entry")
	assert.Equal(t, "consumer", AccountType(res.MRI),
		"AccountType of chosen MRI must be consumer")
	assert.NoError(t, res.Error)
}

// TestEnumerateOne_PrefersCorporateOverConsumer verifies that when the search
// result contains both a consumer user (first) and a corporate user, the
// corporate user is always chosen — regardless of the includeConsumer flag value.
// Metadata (DisplayName, MRI, UserPrincipalName) must come from the corporate
// entry, not from arr[0].
func TestEnumerateOne_PrefersCorporateOverConsumer(t *testing.T) {
	const mixedBody = `[{"displayName":"Personal","mri":"8:live:.cid.aaa"},{"displayName":"Corp User","mri":"8:orgid:bbb","userPrincipalName":"corp@x.com"}]`

	for _, includeConsumer := range []bool{false, true} {
		includeConsumer := includeConsumer
		t.Run(fmt.Sprintf("includeConsumer=%v", includeConsumer), func(t *testing.T) {
			srv := searchServerReturning(http.StatusOK, mixedBody)
			defer srv.Close()

			e := newTestEnumerator(t, srv, nil, false)
			e.SetIncludeConsumer(includeConsumer)

			res := e.EnumerateOne(context.Background(), "corp@x.com")

			// Corporate user must always be preferred regardless of includeConsumer.
			assert.Equal(t, ExistenceYes, res.Exists,
				"includeConsumer=%v: corporate user present must yield ExistenceYes", includeConsumer)
			assert.Equal(t, "Corp User", res.DisplayName,
				"includeConsumer=%v: DisplayName must come from the corporate entry", includeConsumer)
			assert.Equal(t, "8:orgid:bbb", res.MRI,
				"includeConsumer=%v: MRI must be the corporate 8:orgid: MRI", includeConsumer)
			assert.Equal(t, "corp@x.com", res.UserPrincipalName,
				"includeConsumer=%v: UserPrincipalName must come from the corporate entry", includeConsumer)
			assert.Equal(t, "corporate", AccountType(res.MRI),
				"includeConsumer=%v: AccountType of chosen MRI must be corporate", includeConsumer)
			assert.NoError(t, res.Error)
		})
	}
}

// TestEnumerateOne_CorporateOnly_AlwaysFound verifies that a result containing
// only a corporate (8:orgid:) user is ExistenceYes regardless of the
// includeConsumer flag value.
func TestEnumerateOne_CorporateOnly_AlwaysFound(t *testing.T) {
	const corpBody = `[{"displayName":"Jane","mri":"8:orgid:xyz"}]`

	for _, includeConsumer := range []bool{false, true} {
		includeConsumer := includeConsumer
		t.Run(fmt.Sprintf("includeConsumer=%v", includeConsumer), func(t *testing.T) {
			srv := searchServerReturning(http.StatusOK, corpBody)
			defer srv.Close()

			e := newTestEnumerator(t, srv, nil, false)
			e.SetIncludeConsumer(includeConsumer)

			res := e.EnumerateOne(context.Background(), "jane@contoso.com")

			assert.Equal(t, ExistenceYes, res.Exists,
				"includeConsumer=%v: single corporate user must always yield ExistenceYes", includeConsumer)
			assert.Equal(t, "Jane", res.DisplayName)
			assert.Equal(t, "8:orgid:xyz", res.MRI)
			assert.NoError(t, res.Error)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: AccountType — table-driven classification of MRI prefixes
// ---------------------------------------------------------------------------

func TestAccountType(t *testing.T) {
	tests := []struct {
		mri  string
		want string
	}{
		{mri: "8:orgid:abc", want: "corporate"},
		{mri: "8:live:.cid.123", want: "consumer"},
		{mri: "8:orgid:", want: "corporate"}, // prefix-only (no suffix after colon) is still corporate
		{mri: "", want: ""},
		{mri: "weird:mri", want: ""},
		{mri: "8:orgid:some-long-guid-here", want: "corporate"},
		{mri: "8:live:user@contoso.com", want: "consumer"},
		{mri: "8:ORGID:abc", want: ""},  // case-sensitive: uppercase prefix must not match
		{mri: "8:live", want: ""},       // missing trailing colon — not a valid 8:live: prefix
		{mri: "28:orgid:abc", want: ""}, // different prefix digit
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.mri, func(t *testing.T) {
			got := AccountType(tc.mri)
			assert.Equal(t, tc.want, got, "AccountType(%q) should be %q", tc.mri, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: EnumerateWith — callback invoked exactly once per email
// ---------------------------------------------------------------------------

// searchServerPerEmail returns an httptest.Server that returns a user for
// emails in the existSet (200 + user JSON) and an empty array for all others.
func searchServerPerEmail(existEmails map[string]struct{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The email appears as the last path segment (URL-encoded).
		path := r.URL.Path
		parts := strings.Split(path, "/")
		email := parts[len(parts)-1]

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, exists := existEmails[email]; exists {
			_, _ = w.Write([]byte(`[{"displayName":"User","mri":"8:orgid:abc"}]`))
		} else {
			_, _ = w.Write([]byte(`[]`))
		}
	}))
}

func TestEnumerateWith_CallbackPerResult(t *testing.T) {
	// Five emails; two exist, three do not.
	emails := []string{
		"alice@contoso.com",
		"bob@contoso.com",
		"charlie@contoso.com",
		"dave@contoso.com",
		"eve@contoso.com",
	}
	existSet := map[string]struct{}{
		"alice@contoso.com":   {},
		"charlie@contoso.com": {},
	}

	srv := searchServerPerEmail(existSet)
	defer srv.Close()

	e, err := NewEnumerator("tok", "", "", 5*time.Second, false)
	require.NoError(t, err)
	e.searchBaseURL = srv.URL + "/%s"

	var mu sync.Mutex
	var callbackResults []EnumResult

	results := e.EnumerateWith(
		context.Background(),
		emails,
		4, // threads
		0, 0,
		func(r EnumResult) {
			mu.Lock()
			callbackResults = append(callbackResults, r)
			mu.Unlock()
		},
	)

	// Returned slice must have one entry per email.
	require.Len(t, results, len(emails), "EnumerateWith must return one result per email")

	// Callback must be invoked exactly once per email.
	assert.Len(t, callbackResults, len(emails),
		"onResult callback must be invoked exactly once per email")

	// The set of emails seen by the callback must equal the input set.
	cbEmails := make(map[string]struct{}, len(callbackResults))
	for _, r := range callbackResults {
		cbEmails[r.Email] = struct{}{}
	}
	for _, e := range emails {
		assert.Contains(t, cbEmails, e,
			"callback must have been called for email %q", e)
	}

	// Returned results must preserve input order.
	for i, r := range results {
		assert.Equal(t, emails[i], r.Email,
			"results[%d] must correspond to emails[%d]", i, i)
	}
}

// ---------------------------------------------------------------------------
// Test: EnumerateWith — nil callback behaves like Enumerate
// ---------------------------------------------------------------------------

func TestEnumerateWith_NilCallback(t *testing.T) {
	const n = 10
	srv := searchServerReturning(http.StatusOK, `[]`)
	defer srv.Close()

	e, err := NewEnumerator("tok", "", "", 5*time.Second, false)
	require.NoError(t, err)
	e.searchBaseURL = srv.URL + "/%s"

	emails := make([]string, n)
	for i := range emails {
		emails[i] = fmt.Sprintf("user%d@contoso.com", i)
	}

	// EnumerateWith with nil callback must not panic and must return N results.
	withResults := e.EnumerateWith(context.Background(), emails, 4, 0, 0, nil)
	require.Len(t, withResults, n,
		"EnumerateWith(nil) must return one result per email (no panic)")

	// Enumerate is a thin wrapper over EnumerateWith(nil); results must match in length.
	enumResults := e.Enumerate(context.Background(), emails, 4, 0, 0)
	assert.Len(t, enumResults, n,
		"Enumerate must return the same count as EnumerateWith(nil)")

	// Both should return the same emails in the same order.
	for i := range withResults {
		assert.Equal(t, withResults[i].Email, enumResults[i].Email,
			"Enumerate and EnumerateWith(nil) must agree on result[%d].Email", i)
		assert.Equal(t, withResults[i].Exists, enumResults[i].Exists,
			"Enumerate and EnumerateWith(nil) must agree on result[%d].Exists", i)
	}
}

// ---------------------------------------------------------------------------
// Test: EnumerateWith streaming race — non-nil callback under -race
// ---------------------------------------------------------------------------
//
// This test extends TestEnumerate_ConcurrentRefreshNoRace to verify that the
// streaming (onResult callback) surface is also race-clean when a concurrent
// 401→refresh→retry is in flight.
//
// Design mirrors TestEnumerate_ConcurrentRefreshNoRace: the first HTTP request
// returns 401 (triggering refreshOnce), subsequent requests succeed. The
// callback appends under its own mutex, and after the run we assert that:
//   1. No data race was detected by the -race detector.
//   2. The callback was invoked exactly N times (once per email).

func TestEnumerateWith_CallbackRace(t *testing.T) {
	var reqCount atomic.Int32
	var refreshCount atomic.Int32

	// Server: first call → 401, subsequent → 200 with a user.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"displayName":"U","mri":"8:orgid:u"}]`))
	}))
	defer srv.Close()

	e := newTestEnumerator(t, srv, nil, false)
	e.SetRefreshFunc(func(ctx context.Context) (string, error) {
		refreshCount.Add(1)
		return "refreshed-token", nil
	})

	const numEmails = 50
	const numThreads = 8
	emails := make([]string, numEmails)
	for i := range emails {
		emails[i] = fmt.Sprintf("user%d@contoso.com", i)
	}

	var cbMu sync.Mutex
	var cbCount int

	results := e.EnumerateWith(
		context.Background(),
		emails,
		numThreads,
		0, 0,
		func(r EnumResult) {
			cbMu.Lock()
			cbCount++
			cbMu.Unlock()
		},
	)

	// Every email must produce exactly one result.
	require.Len(t, results, numEmails, "must return one result per email")

	// Callback must be invoked exactly once per email.
	assert.Equal(t, numEmails, cbCount,
		"onResult callback must be invoked exactly once per email (race-clean streaming)")

	// Refresh func must be invoked exactly once.
	assert.Equal(t, int32(1), refreshCount.Load(),
		"refresh func must be invoked exactly once across concurrent goroutines")

	// All results must be ExistenceYes.
	for i, r := range results {
		assert.Equal(t, ExistenceYes, r.Exists,
			"result[%d] must be ExistenceYes after successful refresh", i)
	}
}
