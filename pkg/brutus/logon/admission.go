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
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// detectSticky and detectUtilman are swappable seam vars over the RDP check
// entry points so tests can substitute fakes (see sequential_test.go) that
// record invocation order without a live RDP server.
var (
	detectSticky  = rdp.DetectStickyKeys
	detectUtilman = rdp.DetectUtilman
)

// Check selects which logon-screen backdoor check(s) runDetection performs.
type Check int

const (
	// CheckBoth runs sticky-keys then utilman; it is the zero value/default
	// and answers "does this host have a logon backdoor?".
	CheckBoth Check = iota
	// CheckStickyKeys runs only the sticky-keys check (no preceding check, so
	// per-binary attribution is reliable and no downgrade applies).
	CheckStickyKeys
	// CheckUtilman runs only the utilman check.
	CheckUtilman
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
var runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) ([]brutus.Result, bool) {
	noVision := !aiMode

	// Sticky keys and utilman detection run sequentially under the single held
	// decode slot: sticky first, then utilman. The shared-connection design was
	// infeasible (the Rust FFI moves the ConnectionResult out on the first
	// session_new), so each check still opens its own RDP connection and WASM
	// instance. Running them one at a time keeps the decode-slot bound accurate
	// (one decoder per slot, not two concurrent). In CheckBoth mode a positive
	// sticky result never suppresses the utilman check.
	var results []brutus.Result
	var sticky, utilman *brutus.Result

	if checks != CheckUtilman {
		sticky = detectSticky(ctx, target, connectTimeout, timeout, "(sticky-keys)", noVision, fast)
		results = append(results, *sticky)
	}
	if checks != CheckStickyKeys {
		utilman = detectUtilman(ctx, target, connectTimeout, timeout, "(utilman)", noVision, fast)
		results = append(results, *utilman)
	}

	// Contamination-aware downgrade (CheckBoth only): contamination can only
	// occur after a sticky pop, so when sticky is a positive verdict and utilman
	// comes back clean (non-indeterminate), we refuse to claim utilman is clean
	// and mark it indeterminate instead. Presence is already established by the
	// sticky positive; this never downgrades a utilman positive and never
	// upgrades an indeterminate. results[len-1] is the utilman entry here.
	if checks == CheckBoth && sticky.Success && !utilman.Success && !utilman.Indeterminate {
		downgraded := &results[len(results)-1]
		downgraded.Success = false
		downgraded.Indeterminate = true
		downgraded.Banner = "[WARN] Utilman check INDETERMINATE (sticky-keys backdoor present; could not independently confirm utilman — rerun: brutus utilman)"
	}

	hasSuccess := false
	for i := range results {
		if results[i].Success {
			hasSuccess = true
		}
	}
	return results, hasSuccess
}

// CancelledResults returns the sticky + utilman result pair for a host whose
// decode slot was never acquired (context canceled while queued). The host did
// not run, so it must read as INDETERMINATE — never silently clean.
func CancelledResults(target string) []brutus.Result {
	const banner = "[WARN] %s check INDETERMINATE (scan canceled before start — rerun)"
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
