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
	"runtime"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/praetorian-inc/brutus/internal/plugins/rdp"
)

// detectSticky and detectUtilman are swappable seam vars over the RDP check
// entry points so tests can substitute fakes (see sequential_test.go) that
// record invocation order without a live RDP server.
var (
	detectSticky  = rdp.DetectStickyKeysOutcome
	detectUtilman = rdp.DetectUtilmanOutcome
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

// types returns the backdoor types this selector covers, in run order. It is
// the single place the selector is expanded, so the detection path and the
// not-scannable paths cannot disagree about which checks a scan reports.
func (c Check) types() []BackdoorType {
	switch c {
	case CheckStickyKeys:
		return []BackdoorType{BackdoorStickyKeys}
	case CheckUtilman:
		return []BackdoorType{BackdoorUtilman}
	default:
		return []BackdoorType{BackdoorStickyKeys, BackdoorUtilman}
	}
}

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

// contaminatedUtilmanReason explains a utilman check whose clean reading cannot
// be trusted because the preceding sticky-keys check left a window on screen.
const contaminatedUtilmanReason = "sticky-keys check returned a positive, so the screen was contaminated before the utilman trigger; utilman could not be independently confirmed (rerun: brutus utilman)"

// runDetection holds the post-acquire detection body. It is a package-level var
// (paralleling scanTargetFn in cmd/brutus) so tests can swap it for a fake that
// records peak concurrency without a live RDP server. DetectBackdoors acquires a
// decode slot before invoking it.
var runDetection = func(ctx context.Context, target string, connectTimeout, timeout time.Duration, aiMode bool, checks Check, fast bool) []Finding {
	noVision := !aiMode

	var findings []Finding

	if checks != CheckUtilman {
		findings = append(findings, findingFrom(target, detectSticky(ctx, target, connectTimeout, timeout, noVision, fast)))
	}
	if checks != CheckStickyKeys {
		findings = append(findings, findingFrom(target, detectUtilman(ctx, target, connectTimeout, timeout, noVision, fast)))
	}

	downgradeContaminatedUtilman(checks, findings)
	return findings
}

func downgradeContaminatedUtilman(checks Check, findings []Finding) {
	if checks != CheckBoth || len(findings) < 2 {
		return
	}
	sticky, utilman := &findings[0], &findings[len(findings)-1]
	if !sticky.Verdict.Positive() || utilman.Verdict != VerdictClean {
		return
	}
	utilman.Verdict = VerdictIndeterminate
	utilman.Confidence = 0
	utilman.Diagnostics.SkipReason = contaminatedUtilmanReason
}

// CancelledResults returns the findings for a host whose decode slot was never
// acquired (context canceled while queued). The host did not run, so it reads
// as canceled — never silently clean.
func CancelledResults(target string, checks Check) []Finding {
	return terminalFindings(target, checks, VerdictCanceled, "scan canceled before start (rerun)")
}
