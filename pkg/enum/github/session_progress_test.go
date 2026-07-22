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

package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionProgressCall records the arguments of one OnSessionProgress
// invocation, in call order.
type sessionProgressCall struct {
	attempt     int
	maxAttempts int
	lastErr     error
}

// TestOnSessionProgress_InvokedPerAttempt verifies that establishSession
// invokes Enumerator.OnSessionProgress once at the start of every attempt —
// including the first — with a 1-based attempt number, a constant
// maxAttempts (existenceMaxRetries+1), and the previous attempt's error (nil
// on the first call). The /join handler returns HTTP 403 for the first two
// attempts (mirroring GitHub's bot/rate detection stub) and then serves the
// CSRF-bearing page on the third, so the callback must fire exactly 3 times:
// twice with a non-nil lastErr describing the prior 403, and once (the first
// call) with lastErr == nil.
func TestOnSessionProgress_InvokedPerAttempt(t *testing.T) {
	t.Parallel()

	const csrfToken = "csrf-session-progress-token"
	var joinCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, _ *http.Request) {
		n := joinCalls.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body>blocked</body></html>`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<auto-check src="/email_validity_checks">
  <input type="hidden" value="%s">
</auto-check>
</body></html>`, csrfToken)
	})
	mux.HandleFunc("/email_validity_checks", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("value") == "target@example.com" {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422 → exists
		} else {
			w.WriteHeader(http.StatusOK) // 200 → available (sanity-check passes)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e := newTestEnumerator(t, srv, nil, "")
	e.existenceMaxRetries = 4 // survive the 2 forced 403s with room to spare

	var calls []sessionProgressCall
	e.OnSessionProgress = func(attempt, maxAttempts int, lastErr error) {
		calls = append(calls, sessionProgressCall{attempt: attempt, maxAttempts: maxAttempts, lastErr: lastErr})
	}

	results := e.Enumerate(context.Background(), []string{"target@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error, "establishSession must succeed after retrying past the 403 stubs")
	assert.True(t, results[0].Exists, "HTTP 422 from validity endpoint must map to Exists=true")

	require.Len(t, calls, 3, "OnSessionProgress must fire once per attempt: 2 failed + 1 success")
	for i, c := range calls {
		assert.Equal(t, i+1, c.attempt, "call[%d] must report 1-based attempt %d", i, i+1)
		assert.Equal(t, e.existenceMaxRetries+1, c.maxAttempts,
			"call[%d] must report the constant maxAttempts == existenceMaxRetries+1", i)
	}

	assert.NoError(t, calls[0].lastErr, "the first attempt must report lastErr == nil")
	for i := 1; i < len(calls); i++ {
		require.Error(t, calls[i].lastErr, "call[%d] must report the previous attempt's error", i)
		assert.Contains(t, calls[i].lastErr.Error(), "join page returned HTTP 403",
			"call[%d] lastErr must describe the prior attempt's HTTP 403", i)
	}
}

// TestOnSessionProgress_NilCallbackNoPanic guards the library default: when
// OnSessionProgress is left unset (as NewEnumerator does), establishSession
// must not panic on the nil callback, and a normal existence check must still
// succeed.
func TestOnSessionProgress_NilCallbackNoPanic(t *testing.T) {
	t.Parallel()

	webSrv := newWebServer(t, "csrf-nil-progress", map[string]int{
		"alice@example.com": http.StatusUnprocessableEntity,
	})
	e := newTestEnumerator(t, webSrv, nil, "")
	require.Nil(t, e.OnSessionProgress, "NewEnumerator must leave OnSessionProgress nil by default")

	results := e.Enumerate(context.Background(), []string{"alice@example.com"}, 1, 0, 0)

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.True(t, results[0].Exists)
}
