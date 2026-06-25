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

package logon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// withDecodeSlots replaces the process-wide decode semaphore with one of size n
// for the duration of the test, restoring the original in t.Cleanup.
func withDecodeSlots(t *testing.T, n int64) {
	t.Helper()
	orig := decodeSlots
	decodeSlots = semaphore.NewWeighted(n)
	t.Cleanup(func() { decodeSlots = orig })
}

// TestDecodeSlotBound verifies that the process-wide weighted semaphore
// (decodeSlots) bounds the number of concurrent post-acquire detection
// bodies to the configured slot count, while still allowing real parallelism.
//
// The test mirrors the pattern in cmd/brutus/scan_concurrency_test.go:
// swap a package-level seam (runDetection) with a fake that records peak
// concurrency, fire many concurrent DetectBackdoors calls, then assert the
// bound holds and real parallelism occurred.
func TestDecodeSlotBound(t *testing.T) {
	const slotCount int64 = 4
	const goroutines = 50

	// Shrink decodeSlots to a known small size for the duration of this test.
	withDecodeSlots(t, slotCount)

	// Swap runDetection with a fake that:
	//   - increments an atomic counter on entry
	//   - records peak via compare-and-update
	//   - sleeps 10ms to ensure overlap
	//   - decrements on exit
	//   - returns a benign 2-result slice (sticky + utilman)
	// Stub the NLA probe to return NegoScannable so all goroutines exercise the WASM path.
	origProbe := nlaProbe
	nlaProbe = func(ctx context.Context, target string, connectTimeout, readDeadline time.Duration, proxyURL string) rdp.NegoClass {
		return rdp.NegoScannable
	}

	var current, peak atomic.Int64
	origRunDetection := runDetection
	runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
		n := current.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return []brutus.Result{
			{Target: target, ScanType: "sticky_keys"},
			{Target: target, ScanType: "utilman"},
		}, false
	}
	t.Cleanup(func() {
		runDetection = origRunDetection
		nlaProbe = origProbe
	})

	// Fire goroutines concurrent DetectBackdoors calls.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			DetectBackdoors(context.Background(), "host:3389", 3*time.Second, 5*time.Second, false, 0, CheckBoth, "", false, false)
		}()
	}
	wg.Wait()

	observed := peak.Load()
	// The semaphore must cap concurrency at the slot count.
	assert.LessOrEqual(t, observed, slotCount,
		"peak concurrency (%d) must not exceed decodeSlots (%d)", observed, slotCount)
	// Prove real parallelism; if everything ran serially this would be 1.
	assert.GreaterOrEqual(t, observed, int64(2),
		"expected parallel execution under the semaphore, not serial (peak=%d)", observed)
}
