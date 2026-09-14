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

package rdp

import (
	"context"
	"os"
	"testing"
	"time"
)

// backendCompareHostEnv names a live RDP host to compare the two backends
// against. Without it these tests skip, so an ordinary run needs no server.
const backendCompareHostEnv = "BRUTUS_RDP_COMPARE_HOST"

// TestBackendsAgreeOnStickyKeys runs sticky keys detection through both the WASM
// module and the native library against the same host, and requires the verdicts
// to match.
//
// This is the test that justifies the migration. Every heuristic downstream of
// the frames is shared code, so a disagreement can only come from the transport:
// a differently decoded framebuffer, a keystroke that did not arrive, or a
// session that settled differently. Equal verdicts on a real host are the
// strongest evidence available that the native backend can replace the module.
func TestBackendsAgreeOnStickyKeys(t *testing.T) {
	target := requireCompareHost(t)
	p := &Plugin{}

	wasm := withBackend(t, BackendWASM, func() *StickyKeysResult {
		return p.RunStickyKeysCheck(context.Background(), target, "",
			15*time.Second, 30*time.Second, true, CarefulBudget, false)
	})
	native := withBackend(t, BackendGordp, func() *StickyKeysResult {
		return p.RunStickyKeysCheck(context.Background(), target, "",
			15*time.Second, 30*time.Second, true, CarefulBudget, false)
	})

	t.Logf("wasm:   performed=%v verdict=%q confidence=%.2f stabilized-note=%q",
		wasm.Performed, wasm.OverallVerdict, wasm.Confidence, wasm.RegionNote)
	t.Logf("native: performed=%v verdict=%q confidence=%.2f stabilized-note=%q",
		native.Performed, native.OverallVerdict, native.Confidence, native.RegionNote)

	if wasm.Performed != native.Performed {
		t.Errorf("performed differs: wasm=%v (%s) native=%v (%s)",
			wasm.Performed, wasm.SkipReason, native.Performed, native.SkipReason)
	}
	if !wasm.Performed || !native.Performed {
		// Nothing to compare: whichever backend could not run says why above.
		return
	}
	if wasm.OverallVerdict != native.OverallVerdict {
		t.Errorf("verdict differs: wasm=%q native=%q", wasm.OverallVerdict, native.OverallVerdict)
	}
	if wasm.Stabilized != native.Stabilized {
		// Not a failure on its own: settling depends on timing, and a host that
		// paints slowly can legitimately settle for one run and not the other.
		t.Logf("note: stabilized differs (wasm=%v native=%v), which timing alone can explain",
			wasm.Stabilized, native.Stabilized)
	}
}

// TestBackendsAgreeOnUtilman is the same comparison for the Win+U trigger.
func TestBackendsAgreeOnUtilman(t *testing.T) {
	target := requireCompareHost(t)
	p := &Plugin{}

	wasm := withBackend(t, BackendWASM, func() *UtilmanResult {
		return p.RunUtilmanCheck(context.Background(), target, "",
			15*time.Second, 30*time.Second, true, CarefulBudget, false)
	})
	native := withBackend(t, BackendGordp, func() *UtilmanResult {
		return p.RunUtilmanCheck(context.Background(), target, "",
			15*time.Second, 30*time.Second, true, CarefulBudget, false)
	})

	t.Logf("wasm:   performed=%v verdict=%q confidence=%.2f",
		wasm.Performed, wasm.OverallVerdict, wasm.Confidence)
	t.Logf("native: performed=%v verdict=%q confidence=%.2f",
		native.Performed, native.OverallVerdict, native.Confidence)

	if wasm.Performed != native.Performed {
		t.Errorf("performed differs: wasm=%v (%s) native=%v (%s)",
			wasm.Performed, wasm.SkipReason, native.Performed, native.SkipReason)
	}
	if !wasm.Performed || !native.Performed {
		return
	}
	if wasm.OverallVerdict != native.OverallVerdict {
		t.Errorf("verdict differs: wasm=%q native=%q", wasm.OverallVerdict, native.OverallVerdict)
	}
}

// withBackend runs fn with the given backend selected, restoring the previous
// selection afterwards.
//
// Windows Server allows only two concurrent RDP sessions, so the two runs are
// deliberately sequential rather than parallel: overlapping them would exhaust
// the host and produce logoffs that look like detection failures.
func withBackend[T any](t *testing.T, backend Backend, fn func() T) T {
	t.Helper()

	previous, had := os.LookupEnv(backendEnvVar)
	value := ""
	if backend == BackendGordp {
		value = "gordp"
	}
	t.Setenv(backendEnvVar, value)

	result := fn()

	if had {
		t.Setenv(backendEnvVar, previous)
	}
	return result
}

func requireCompareHost(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping backend comparison in short mode")
	}
	target := os.Getenv(backendCompareHostEnv)
	if target == "" {
		t.Skipf("%s is not set; see GROK.md in the gordp repo for the test servers",
			backendCompareHostEnv)
	}
	return target
}
