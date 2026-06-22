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
	"fmt"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// decodeSlotsPerCPU sizes the process-wide decode-slot budget relative to
// GOMAXPROCS. The RDP detection body is a mix of CPU-bound WASM decode and
// blocking I/O, so we allow modestly more in-flight sessions than cores.
const decodeSlotsPerCPU = 1.5

// decodeSlots bounds how many DetectBackdoors detection bodies may run
// concurrently across the whole process. It is process-wide (not per-errgroup)
// so the gate spans both the host fan-out errgroup and the single-target path.
var decodeSlots = semaphore.NewWeighted(decodeSlotCount())

// decodeSlotCount returns the number of concurrent decode slots, at least 1.
func decodeSlotCount() int64 {
	n := int64(float64(runtime.GOMAXPROCS(0)) * decodeSlotsPerCPU)
	if n < 1 {
		n = 1
	}
	return n
}

// DecodeSlotCount exposes the configured decode-slot budget for callers that
// want to warn when host concurrency greatly exceeds the CPU-bound decode bound.
func DecodeSlotCount() int64 {
	return decodeSlotCount()
}

// runDetection holds the post-acquire detection body. It is a package-level var
// (paralleling scanTargetFn in cmd/brutus) so tests can swap it for a fake that
// records peak concurrency without a live RDP server. DetectBackdoors acquires a
// decode slot before invoking it.
var runDetection = func(ctx context.Context, target string, timeout time.Duration, aiMode bool) ([]brutus.Result, bool) {
	noVision := !aiMode

	// Sticky keys and utilman detection use independent RDP connections and WASM
	// instances (each instance has isolated linear memory; see
	// internal/plugins/rdp/wasm.go), so the two checks run concurrently to halve
	// per-host wall-clock time. Output order (sticky first, utilman second) is
	// preserved regardless of which goroutine finishes first.
	var stickyResult, utilmanResult *brutus.Result
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		stickyResult = rdp.DetectStickyKeys(ctx, target, timeout, "(sticky-keys)", noVision)
	}()
	go func() {
		defer wg.Done()
		utilmanResult = rdp.DetectUtilman(ctx, target, timeout, "(utilman)", noVision)
	}()
	wg.Wait()

	results := []brutus.Result{*stickyResult, *utilmanResult}
	hasSuccess := stickyResult.Success || utilmanResult.Success
	return results, hasSuccess
}

// cancelledResults returns the sticky + utilman result pair for a host whose
// decode slot was never acquired (context cancelled while queued). The host did
// not run, so it must read as INDETERMINATE — never silently clean.
func cancelledResults(target string) []brutus.Result {
	const banner = "[WARN] %s check INDETERMINATE (scan cancelled before start — rerun)"
	return []brutus.Result{
		{
			Protocol:      "rdp",
			Target:        target,
			Username:      "(sticky-keys)",
			ScanType:      "sticky_keys",
			Indeterminate: true,
			Banner:        fmt.Sprintf(banner, "Sticky keys"),
		},
		{
			Protocol:      "rdp",
			Target:        target,
			Username:      "(utilman)",
			ScanType:      "utilman",
			Indeterminate: true,
			Banner:        fmt.Sprintf(banner, "Utilman"),
		},
	}
}
