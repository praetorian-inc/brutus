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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectStickyKeysOutcome_ConnectionError(t *testing.T) {
	ctx := context.Background()
	out := DetectStickyKeysOutcome(ctx, "127.0.0.1:1", 2*time.Second, 2*time.Second, false, false)

	require.NotNil(t, out)
	assert.Equal(t, BackdoorStickyKeys, out.Check)
	assert.False(t, out.Performed)
	assert.True(t, out.Unreachable, "a refused dial is terminal-unreachable")
}

func TestDetectStickyKeysOutcome_UnroutableHost(t *testing.T) {
	ctx := context.Background()
	out := DetectStickyKeysOutcome(ctx, "198.51.100.1:3389", 500*time.Millisecond, 500*time.Millisecond, false, false)

	require.NotNil(t, out)
	assert.Equal(t, BackdoorStickyKeys, out.Check)
	assert.False(t, out.Performed)
}

func TestDetectUtilmanOutcome_ConnectionError(t *testing.T) {
	ctx := context.Background()
	out := DetectUtilmanOutcome(ctx, "127.0.0.1:1", 2*time.Second, 2*time.Second, false, false)

	require.NotNil(t, out)
	assert.Equal(t, BackdoorUtilman, out.Check)
	assert.False(t, out.Performed)
	assert.True(t, out.Unreachable)
}

func TestDetectUtilmanOutcome_UnroutableHost(t *testing.T) {
	ctx := context.Background()
	out := DetectUtilmanOutcome(ctx, "198.51.100.1:3389", 500*time.Millisecond, 500*time.Millisecond, false, false)

	require.NotNil(t, out)
	assert.Equal(t, BackdoorUtilman, out.Check)
	assert.False(t, out.Performed)
}

// TestStabilizedVerdict verifies the cardinal false-negative guard (I2): only a
// "clean" verdict on an unstabilized render is downgraded to "indeterminate".
// Positive verdicts (backdoor_confirmed, backdoor_likely, vulnerable) must never
// be downgraded regardless of stabilization, and "indeterminate" input is left
// unchanged.
//
// The fast flag adds the never-clean invariant: in fast mode, even a stabilized
// clean becomes indeterminate. This is the key never-clean assertion from Task 3
// of the fast-mode plan (Phase 2).
//
// RED until the developer:
//  1. Adds `fast bool` parameter to stabilizedVerdict (detect.go:381)
//  2. Implements: if verdict == "clean" && (!stabilized || fast) { return verdictIndeterminate }
func TestStabilizedVerdict(t *testing.T) {
	tests := []struct {
		name       string
		verdict    string
		stabilized bool
		fast       bool
		want       string
	}{
		// --- Original careful-mode rows (fast=false, preserving existing behavior) ---
		{
			name:       "clean unstabilized -> indeterminate (cardinal flip)",
			verdict:    "clean",
			stabilized: false,
			fast:       false,
			want:       verdictIndeterminate,
		},
		{
			name:       "clean stabilized -> clean (no flip when careful)",
			verdict:    "clean",
			stabilized: true,
			fast:       false,
			want:       "clean",
		},
		{
			name:       "backdoor_confirmed unstabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_confirmed",
			stabilized: false,
			fast:       false,
			want:       "backdoor_confirmed",
		},
		{
			name:       "backdoor_likely unstabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_likely",
			stabilized: false,
			fast:       false,
			want:       "backdoor_likely",
		},
		{
			name:       "vulnerable unstabilized -> unchanged (positive never downgraded)",
			verdict:    "vulnerable",
			stabilized: false,
			fast:       false,
			want:       "vulnerable",
		},
		{
			name:       "indeterminate unstabilized -> unchanged (already indeterminate)",
			verdict:    verdictIndeterminate,
			stabilized: false,
			fast:       false,
			want:       verdictIndeterminate,
		},
		// --- New fast-mode rows: the NEVER-CLEAN invariant ---
		{
			// THE KEY ASSERTION: fast + clean + stabilized → indeterminate.
			// A fast triage pass may NEVER yield a confident clean verdict;
			// stabilized clean must become indeterminate so operators rerun without --fast.
			name:       "fast + clean + stabilized -> indeterminate (never-clean invariant)",
			verdict:    "clean",
			stabilized: true,
			fast:       true,
			want:       verdictIndeterminate,
		},
		{
			name:       "fast + clean + !stabilized -> indeterminate (both conditions fire)",
			verdict:    "clean",
			stabilized: false,
			fast:       true,
			want:       verdictIndeterminate,
		},
		{
			name:       "fast + backdoor_confirmed + stabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_confirmed",
			stabilized: true,
			fast:       true,
			want:       "backdoor_confirmed",
		},
		{
			name:       "fast + backdoor_likely + stabilized -> unchanged (positive never downgraded)",
			verdict:    "backdoor_likely",
			stabilized: true,
			fast:       true,
			want:       "backdoor_likely",
		},
		{
			name:       "fast + vulnerable + stabilized -> unchanged (vulnerable is a positive observation)",
			verdict:    "vulnerable",
			stabilized: true,
			fast:       true,
			want:       "vulnerable",
		},
		{
			name:       "fast + indeterminate -> unchanged (already indeterminate)",
			verdict:    verdictIndeterminate,
			stabilized: true,
			fast:       true,
			want:       verdictIndeterminate,
		},
		{
			// Explicit careful+clean+stabilized row to lock the "careful preserves clean" behavior.
			name:       "careful + clean + stabilized -> clean (fast off preserves clean)",
			verdict:    "clean",
			stabilized: true,
			fast:       false,
			want:       "clean",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stabilizedVerdict(tc.verdict, tc.stabilized, tc.fast)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSettled verifies the wall-clock settle decision used by pumpSession:
// a framebuffer counts as settled only once BOTH a minimum pump time
// (minPump) has elapsed since the pump started AND the framebuffer has
// been unchanged for at least the quiet window (quietWindow). A brief
// mid-paint pause that is shorter than the quiet window must NOT be treated as
// settled, which is the root cause of the half-painted-frame capture bug.
//
// After the SettleBudget refactor, settled() takes a budget parameter;
// these tests use CarefulBudget to verify the legacy behavior is unchanged.
func TestSettled(t *testing.T) {
	start := time.Time{}

	tests := []struct {
		name       string
		now        time.Duration // since start
		lastChange time.Duration // since start
		want       bool
	}{
		{
			name:       "before minPumpTime never settles even if quiet",
			now:        CarefulBudget.minPump - 100*time.Millisecond,
			lastChange: 0, // quiet the whole time
			want:       false,
		},
		{
			name:       "after minPumpTime but quiet window not yet elapsed (mid-paint pause)",
			now:        CarefulBudget.minPump + 500*time.Millisecond,
			lastChange: CarefulBudget.minPump + 500*time.Millisecond - (CarefulBudget.quietWindow - 100*time.Millisecond),
			want:       false,
		},
		{
			name:       "after minPumpTime and quiet window elapsed -> settled",
			now:        CarefulBudget.minPump + CarefulBudget.quietWindow + 100*time.Millisecond,
			lastChange: 0,
			want:       true,
		},
		{
			name:       "quiet window satisfied but minPumpTime not -> not settled",
			now:        CarefulBudget.quietWindow + 100*time.Millisecond,
			lastChange: 0,
			want:       CarefulBudget.quietWindow+100*time.Millisecond >= CarefulBudget.minPump,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := settled(start, start.Add(tc.lastChange), start.Add(tc.now), CarefulBudget)
			assert.Equal(t, tc.want, got)
		})
	}
}

// makeFrame builds a width*height RGBA buffer filled with a uniform gray value.
func makeFrame(width, height uint32, gray byte) []byte {
	buf := make([]byte, int(width)*int(height)*4)
	for i := 0; i < len(buf); i += 4 {
		buf[i] = gray
		buf[i+1] = gray
		buf[i+2] = gray
		buf[i+3] = 255
	}
	return buf
}

// flipPixels brightens the first n pixels of buf by delta (clamped at 255) so
// their inter-frame brightness diff exceeds changeThreshold.
func flipPixels(buf []byte, n int, delta byte) {
	for p := 0; p < n; p++ {
		i := p * 4
		if i+2 >= len(buf) {
			break
		}
		v := int(buf[i]) + int(delta)
		if v > 255 {
			v = 255
		}
		buf[i] = byte(v)
		buf[i+1] = byte(v)
		buf[i+2] = byte(v)
	}
}

// TestFramesQuiet verifies the noise-tolerant inter-frame settle decision used by
// pumpSession: a frame counts as "quiet" only when the number of pixels whose
// brightness changed by more than changeThreshold is at most noisePixels (from
// the budget). A blinking console cursor (a handful of changed pixels) must read
// as quiet so a cmd window can settle, while a window repaint (tens of thousands
// of changed pixels) must NOT be treated as quiet.
//
// After the SettleBudget refactor, framesQuiet() takes a budget parameter;
// these tests use CarefulBudget to verify the legacy behavior is unchanged.
func TestFramesQuiet(t *testing.T) {
	const w, h = uint32(200), uint32(200) // 40,000 pixels

	tests := []struct {
		name      string
		changedPx int
		wantQuiet bool
	}{
		{
			name:      "identical frames are quiet",
			changedPx: 0,
			wantQuiet: true,
		},
		{
			name:      "blinking cursor (few hundred px) is quiet",
			changedPx: 300,
			wantQuiet: true,
		},
		{
			name:      "exactly at CarefulBudget noisePixels is quiet",
			changedPx: CarefulBudget.noisePixels,
			wantQuiet: true,
		},
		{
			name:      "one above CarefulBudget noisePixels is not quiet",
			changedPx: CarefulBudget.noisePixels + 1,
			wantQuiet: false,
		},
		{
			name:      "window repaint (tens of thousands px) is not quiet",
			changedPx: 30000,
			wantQuiet: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := makeFrame(w, h, 100)
			cur := makeFrame(w, h, 100)
			flipPixels(cur, tc.changedPx, changeThreshold+20) // diff well above threshold

			got := framesQuiet(prev, cur, w, h, CarefulBudget)
			assert.Equal(t, tc.wantQuiet, got)
		})
	}
}

// TestConsoleGate_ComposesWithStabilizedVerdict locks the composition invariant:
// after the console gate downgrades backdoor_likely → indeterminate, the
// stabilizedVerdict pass-through must leave "indeterminate" unchanged. Neither
// fast=true nor stabilized=false should re-promote or flip indeterminate to clean.
// This is a guard test (GREEN on arrival once stabilizedVerdict exists) that
// prevents future regressions in the gate↔stabilized composition.
func TestConsoleGate_ComposesWithStabilizedVerdict(t *testing.T) {
	tests := []struct {
		name       string
		stabilized bool
		fast       bool
	}{
		{"indeterminate + !stabilized + !fast → indeterminate", false, false},
		{"indeterminate + stabilized + !fast → indeterminate", true, false},
		{"indeterminate + !stabilized + fast → indeterminate", false, true},
		{"indeterminate + stabilized + fast → indeterminate", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate: gate turned backdoor_likely → indeterminate; now stabilizedVerdict runs.
			got := stabilizedVerdict(verdictIndeterminate, tc.stabilized, tc.fast)
			assert.Equal(t, verdictIndeterminate, got,
				"stabilizedVerdict must leave gate-downgraded indeterminate unchanged (stabilized=%v fast=%v)",
				tc.stabilized, tc.fast)
			assert.NotEqual(t, "clean", got,
				"composition CARDINAL: gate output must never become clean after stabilizedVerdict")
			assert.NotEqual(t, "backdoor_likely", got,
				"composition CARDINAL: gate output must never be re-promoted to backdoor_likely")
		})
	}
}

// TestCheckLabeling verifies the two entry points stamp distinct check types,
// which is what the JSONL "check" field and per-binary attribution key on.
func TestCheckLabeling(t *testing.T) {
	ctx := context.Background()

	sticky := DetectStickyKeysOutcome(ctx, "198.51.100.1:3389", 500*time.Millisecond, 500*time.Millisecond, false, false)
	require.NotNil(t, sticky)
	assert.Equal(t, BackdoorStickyKeys, sticky.Check)

	utilman := DetectUtilmanOutcome(ctx, "198.51.100.1:3389", 500*time.Millisecond, 500*time.Millisecond, false, false)
	require.NotNil(t, utilman)
	assert.Equal(t, BackdoorUtilman, utilman.Check)
}

// Outcome normalization: the dial-failure vs. other-failure distinction must
// survive the hop out of this package, because pkg/brutus/logon turns
// Unreachable into a TERMINAL verdict and every other !Performed failure into
// a rerun candidate. Flattening the two together here would silently make
// unreachable hosts retryable, or worse, clean.

func TestStickyOutcome_PreservesUnreachable(t *testing.T) {
	out := stickyOutcome(&StickyKeysResult{Performed: false, Unreachable: true, SkipReason: "connection failed: i/o timeout"})
	assert.True(t, out.Unreachable, "dial failure must stay distinguishable as unreachable")
	assert.False(t, out.Performed)
	assert.Equal(t, "connection failed: i/o timeout", out.SkipReason)
	assert.Equal(t, BackdoorStickyKeys, out.Check)
}

func TestStickyOutcome_WasmFailureIsNotUnreachable(t *testing.T) {
	out := stickyOutcome(&StickyKeysResult{Performed: false, Unreachable: false, SkipReason: "wasm instance: boom"})
	assert.False(t, out.Unreachable, "a non-dial failure must not read as unreachable")
	assert.False(t, out.Performed)
	assert.Equal(t, "wasm instance: boom", out.SkipReason)
}

func TestUtilmanOutcome_PreservesUnreachable(t *testing.T) {
	out := utilmanOutcome(&UtilmanResult{Performed: false, Unreachable: true, SkipReason: "connection failed: refused"})
	assert.True(t, out.Unreachable)
	assert.False(t, out.Performed)
	assert.Equal(t, BackdoorUtilman, out.Check)
}

func TestUtilmanOutcome_WasmFailureIsNotUnreachable(t *testing.T) {
	out := utilmanOutcome(&UtilmanResult{Performed: false, Unreachable: false, SkipReason: "wasm init: boom"})
	assert.False(t, out.Unreachable)
	assert.False(t, out.Performed)
}

// TestOutcome_CarriesEveryDiagnostic pins that normalization is lossless for
// the fields consumers render. A dropped field here reappears downstream as a
// verdict nobody can explain.
func TestOutcome_CarriesEveryDiagnostic(t *testing.T) {
	out := stickyOutcome(&StickyKeysResult{
		Performed:         true,
		Stabilized:        true,
		OverallVerdict:    "backdoor_likely",
		Confidence:        0.62,
		HeuristicResult:   "12% dark delta",
		VisionResult:      "dark console-like window",
		RegionNote:        "console-shaped",
		SessionTerminated: true,
		TerminationReason: "server initiated disconnect",
	})

	assert.Equal(t, "backdoor_likely", out.Verdict)
	assert.InDelta(t, 0.62, out.Confidence, 1e-9)
	assert.True(t, out.Stabilized)
	assert.Equal(t, "12% dark delta", out.Heuristic)
	assert.Equal(t, "dark console-like window", out.Vision)
	assert.Equal(t, "console-shaped", out.RegionNote)
	assert.True(t, out.SessionTerminated)
	assert.Equal(t, "server initiated disconnect", out.TerminationReason)
}

func TestOutcome_CarriesScreenshots(t *testing.T) {
	baseline := []byte{0x89, 0x50, 0x4E, 0x47, 0x01}
	response := []byte{0x89, 0x50, 0x4E, 0x47, 0x02}

	sticky := stickyOutcome(&StickyKeysResult{BaselinePNG: baseline, ResponsePNG: response})
	assert.Equal(t, baseline, sticky.BaselinePNG)
	assert.Equal(t, response, sticky.ResponsePNG)

	utilman := utilmanOutcome(&UtilmanResult{BaselinePNG: baseline, ResponsePNG: response})
	assert.Equal(t, baseline, utilman.BaselinePNG)
	assert.Equal(t, response, utilman.ResponsePNG)
}

func TestEncodeFramePNG(t *testing.T) {
	assert.Nil(t, encodeFramePNG(nil, 1, 1))
	assert.Nil(t, encodeFramePNG([]byte{0, 0, 0, 255}, 0, 1))
	assert.Nil(t, encodeFramePNG([]byte{0, 0, 0}, 1, 1))
	assert.Nil(t, encodeFramePNG(make([]byte, 4), 2, 1))
	assert.Nil(t, encodeFramePNG([]byte{1}, ^uint32(0), ^uint32(0)))

	pngData := encodeFramePNG([]byte{0, 0, 0, 255}, 1, 1)
	require.NotEmpty(t, pngData)
	assert.Equal(t, byte(0x89), pngData[0])
	assert.Equal(t, byte(0x50), pngData[1])
}

// TestSafeFilenameComponentCannotEscapeADirectory pins the traversal fix. A target
// reaches dumpFrame straight from the scan list, and ParseTarget validates a host's
// shape but not its contents, so a hostile targets-file line arrives intact.
func TestSafeFilenameComponentCannotEscapeADirectory(t *testing.T) {
	base := filepath.Clean("/base/dir")

	for _, target := range []string{
		"10.0.0.5:3389",
		"../../../../../../tmp/pwned:3389",
		"../../.ssh/authorized_keys:1",
		`..\..\windows\system32\x:3389`,
		"..",
		"../",
		"/etc/passwd:3389",
		"host/../../../escape:3389",
	} {
		path := filepath.Join(base, safeFilenameComponent(target)+"_sticky_keys_baseline.png")
		assert.Equal(t, base, filepath.Dir(path), "target %q escaped the debug directory: %s", target, path)
	}
}

// TestSafeFilenameComponentKeepsTargetsReadable is the other half: the sanitizer has to
// leave a debug capture identifiable, or it defeats the purpose of the dump.
func TestSafeFilenameComponentKeepsTargetsReadable(t *testing.T) {
	assert.Equal(t, "10.0.0.5_3389", safeFilenameComponent("10.0.0.5:3389"))
	assert.Equal(t, "host.example.com_3389", safeFilenameComponent("host.example.com:3389"))
	// An IPv6 address keeps its digits and separators-turned-underscores.
	assert.Equal(t, "_2001_db8__1__3389", safeFilenameComponent("[2001:db8::1]:3389"))
}

// TestDumpFrameRefusesToWriteOutsideTheDebugDirectory exercises dumpFrame end to end
// with a traversing target, and asserts nothing lands outside the directory it was given.
func TestDumpFrameRefusesToWriteOutsideTheDebugDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "shots")
	canary := filepath.Join(parent, "pwned_3389_sticky_keys_baseline.png")

	// A 1x1 RGBA frame is enough for saveRGBAScreenshot to produce a real PNG.
	dumpFrame(dir, "../pwned:3389", "sticky_keys", "baseline", []byte{0, 0, 0, 255}, 1, 1)

	_, err := os.Stat(canary)
	assert.True(t, os.IsNotExist(err), "a traversing target must not write into the parent directory")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the capture still lands, inside the debug directory")
	assert.Equal(t, ".._pwned_3389_sticky_keys_baseline.png", entries[0].Name())
}
